/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsserver.h>
#include <dnsmsg.h>

void
dns::Server::HandleMessage(
   MessageMode mode,
   void *buf, size_t len,
   const struct sockaddr *addr,
   ResponseMap &map,
   const std::function<void(const void *, size_t, error *)> &reply,
   error *err
)
{
   Message msg;
   ResponseCode rc = ResponseCode::ServerFailure;

   ParseMessage(buf, len, &msg, err);
   if (ERROR_FAILED(err))
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

   if (msg.Header->Response)
   {
      if ((int)mode & (int)MessageMode::Client)
         map.OnResponse(addr, buf, len, msg, err);
      return;
   }
   else if (!((int)mode & (int)MessageMode::Server))
      return;

   // Several DNS servers reject more than one question per packet.
   //
   if (msg.Header->QuestionCount.Get() != 1)
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

   TryForwardPacket(addr, buf, len, msg, reply, err);
   ERROR_CHECK(err);

exit:;
   if (ERROR_FAILED(err))
      goto errorReply;
   return;
errorReply:
   error_clear(err);
   if (((int)mode & (int)MessageMode::Server) &&
       len > 2 &&
       (len < 3 || !((MessageHeader*)buf)->Response))
   {
      MessageWriter writer;

      writer.Header->Id.Put(((MessageHeader*)buf)->Id.Get());
      writer.Header->Response = 1;
      writer.Header->ResponseCode = (unsigned)rc;
      writer.Header->RecursionAvailable = 1;

      for (auto q : msg.Questions)
      {
         auto qq = writer.AddQuestion(err);
         if (ERROR_FAILED(err))
            break;
         qq->Name = std::move(q.Name);
         *qq->Attrs = *q.Attrs;
      }

      auto vec = writer.Serialize(err);

      if (ERROR_FAILED(err))
      {
         error_clear(err);
         writer.Header->QuestionCount.Put(0);
         reply(writer.Header, sizeof(*writer.Header), err);
      }
      else
      {
         reply(vec.data(), vec.size(), err);
      }
      error_clear(err);
   }
}
