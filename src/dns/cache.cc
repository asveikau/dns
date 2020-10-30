/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsserver.h>
#include <dnsmsg.h>

#include <sqlite3.h>

#include <common/time.h>

//
// For now, the cache is an in-memory sqlite database.  It is written that way
// with the idea that perhaps later it persists on-disk between server restarts.
//

void
dns::Server::InitializeCache(error *err)
{
   static const char *schema[] =
   {
      "create table dns_cache("
         "name STRING,"
         "queried_type INTEGER,"
         "queried_class INTEGER,"
         "response_code INTEGER,"
         "response_time INTEGER,"
         "response_ttl INTEGER,"
         "response_type INTEGER,"
         "response_class INTEGER,"
         "response BLOB"
      ")",
      "create index cache_by_string on dns_cache(name, response_type)",
      NULL,
   };

   if (cacheDb.is_open())
      goto exit;

   cacheDb.open(":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr, err);
   ERROR_CHECK(err);

   cacheDb.exec(schema, err);
   ERROR_CHECK(err);

exit:;
}

bool
dns::Server::TryCache(
   const Message &msg,
   const std::function<void(const void *, size_t, error *)> &reply
)
{
   error errStorage;
   error *err = &errStorage;
   bool found = false;
   sqlite::statement stmt;

   if (!msg.Header || msg.Questions.size() != 1)
      goto exit;

   InitializeCache(err);
   ERROR_CHECK(err);

   cacheDb.prepare(
      "SELECT response_code, response_type, response_class, response_time, response_ttl, response "
              "FROM dns_cache "
              "WHERE name = ? AND queried_type = ? AND queried_class = ?",
      stmt,
      err
   );
   ERROR_CHECK(err);

   stmt.bind(0, msg.Questions[0].Name, err);
   ERROR_CHECK(err);
   stmt.bind(1, (int64_t)msg.Questions[0].Attrs->Type.Get(), err);
   ERROR_CHECK(err);
   stmt.bind(2, (int64_t)msg.Questions[0].Attrs->Class.Get(), err);
   ERROR_CHECK(err);

   if (stmt.step(err))
   {
      MessageWriter response;

      response.Header->Id = msg.Header->Id;

      auto q = response.AddQuestion(err);
      ERROR_CHECK(err);

      try
      {
         q->Name = msg.Questions[0].Name;
      }
      catch (const std::bad_alloc &)
      {
         ERROR_SET(err, nomem);
      }
      *q->Attrs = *msg.Questions[0].Attrs;

      uint64_t current_time = get_current_time();
      std::vector<char> blob;
      do
      {
         int64_t rc, type, class_, time, ttl;

         stmt.column_multi(err, 0, rc, type, class_, time, ttl, blob);
         ERROR_CHECK(err);

         if (time && (time > current_time || time + ttl < current_time))
         {
            // Stale TTL anywhere should mean discard cache.
            //
            goto exit;
         }

         if (rc != (int)ResponseCode::NoError)
         {
            response.Header->ResponseCode = rc;
            break;
         }

         auto answer = response.AddAnswer((uint16_t)blob.size(), err);
         ERROR_CHECK(err);

         try
         {
            answer->Name = msg.Questions[0].Name;
         }
         catch (const std::bad_alloc &)
         {
            ERROR_SET(err, nomem);
         }
         answer->Attrs->Type.Put(type);
         answer->Attrs->Class.Put(class_);
         answer->Attrs->Ttl.Put(time + ttl - current_time);
         memcpy(answer->Attrs->Data, blob.data(), blob.size());
      } while (stmt.step(err));
      ERROR_CHECK(err);

      blob = response.Serialize(err);
      ERROR_CHECK(err);

      reply(blob.data(), blob.size(), err);
      ERROR_CHECK(err);
      found = true;
   }
   ERROR_CHECK(err);

exit:
   return found;
}

void
dns::Server::CacheReply(const void *buf, size_t len)
{
   Message msg;
   error errStorage;
   error *err = &errStorage;
   sqlite::statement stmt;
   uint64_t current_time = get_current_time();

   InitializeCache(err);
   ERROR_CHECK(err);

   ParseMessage(buf, len, &msg, err);
   ERROR_CHECK(err);

   if (!msg.Header || msg.Questions.size() != 1)
      goto exit;

   cacheDb.prepare(
      "DELETE FROM dns_cache WHERE name = ? AND queried_type = ? AND queried_class = ?",
      stmt,
      err
   );

   stmt.bind_multi(
      err, 0,
      msg.Questions[0].Name,
      (int64_t)msg.Questions[0].Attrs->Type.Get(),
      (int64_t)msg.Questions[0].Attrs->Class.Get()
   );
   ERROR_CHECK(err);

   stmt.step(err);
   ERROR_CHECK(err);

   if (!msg.Header->AnswerCount.Get())
   {
      cacheDb.prepare(
         "INSERT INTO dns_cache VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
         stmt,
         err
      );
      ERROR_CHECK(err);
      stmt.bind_multi(
         err, 0,
         msg.Questions[0].Name,
         (int64_t)msg.Questions[0].Attrs->Type.Get(),
         (int64_t)msg.Questions[0].Attrs->Class.Get(),
         (int64_t)msg.Header->ResponseCode,

         // XXX: cache errors for 5 minutes.
         // This is kind of arbitrary.
         //
         current_time,
         (int64_t)(5*60)
      );
      ERROR_CHECK(err);

      stmt.step(err);
      ERROR_CHECK(err);
   }
   else
   {
      Record *rec, *end;

      for (rec = msg.Answers, end = rec+msg.Header->AnswerCount.Get(); rec < end; ++rec)
      {
         cacheDb.prepare(
            "INSERT INTO dns_cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            stmt,
            err
         );

         stmt.bind_multi(
            err, 0,
            msg.Questions[0].Name,
            (int64_t)msg.Questions[0].Attrs->Type.Get(),
            (int64_t)msg.Questions[0].Attrs->Class.Get(),
            (int64_t)msg.Header->ResponseCode,
            current_time,
            (int64_t)rec->Attrs->Ttl.Get(),
            (int64_t)rec->Attrs->Type.Get(),
            (int64_t)rec->Attrs->Class.Get()
         );
         ERROR_CHECK(err);

         stmt.bind(8, rec->Attrs->Data, rec->Attrs->Length.Get(), err);
         ERROR_CHECK(err);

         stmt.step(err);
         ERROR_CHECK(err);
      }
   }

exit:;
}
