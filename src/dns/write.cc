/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsproto.h>
#include <dnsmsg.h>

#include <algorithm>
#include <map>

void
dns::I16::Put(uint16_t value)
{
   auto p = (unsigned char*)&this->value;
   p[0] = (value >> 8);
   p[1] = (value & 0xff);
}

void
dns::I32::Put(uint32_t value)
{
   auto p = (unsigned char*)&this->value;
   p[0] = (value >> 24);
   p[1] = (value >> 16);
   p[2] = (value >> 8);
   p[3] = (value & 0xff);
}

namespace
{

struct StringTable
{
   struct MapComp
   {
      bool operator()(const char *a, const char *b) const { return strcmp(a,b) < 0; };
   };
   std::map<const char *, int, MapComp> priorOffsets;
   int OnInsert(const char *string, int currentOffset)
   {
      auto existing = priorOffsets.find(string);
      if (existing != priorOffsets.end())
      {
         return existing->second;
      }
      priorOffsets[string] = currentOffset;
      return -1;
   }
};

} // end namespace

std::vector<char>
dns::MessageWriter::Serialize(error *err)
{
   std::vector<char> r;
   StringTable table;

   try
   {
      auto hdr = (const char*)Header;
      r.insert(r.end(), hdr, hdr+sizeof(*Header));

      auto writeNameComponents = [&] (const char *p, size_t len) -> void
      {
         while (len)
         {
            size_t l = len;
            int shift = 0;

            int priorOffset = table.OnInsert(p, r.size());
            if (priorOffset >= 0)
            {
               unsigned char sz[] =
               {
                  (unsigned char)(0xc0U | (priorOffset >> 8)),
                  (unsigned char)(priorOffset & 0xff),
               };
               r.push_back(sz[0]);
               r.push_back(sz[1]);
               return;
            }

            auto q = p;
            while (q < p+len && *q != '.')
               ++q;
            if (q < p+len && *q == '.')
            {
               l = q-p;
               shift = 1;
            }

            if (l >= 64)
            {
               error_set_unknown(err, "Invalid length");
               return;
            }

            r.push_back((char)l);
            r.insert(r.end(), p, p+l);

            l += shift;
            p += l;
            len -= l;
         }

         r.push_back(0);
      };

      auto writeName = [&] (const std::string &str) -> void
      {
         writeNameComponents(str.c_str(), str.length());
      };

      for (auto &q : Questions)
      {
         auto p = (const char*)q.Attrs;
         writeName(q.Name);
         ERROR_CHECK(err);
         r.insert(r.end(), p, p+sizeof(*q.Attrs));
      }

      for (auto rlist : {&answerReqs, &authorityReqs, &additlRecs})
      {
         for (auto &rr : *rlist)
         {
            auto p = (const char*)rr.Attrs;
            writeName(rr.Name);
            ERROR_CHECK(err);
            r.insert(r.end(), p, p+offsetof(RecordAttrs, Data)+rr.Attrs->Length.Get());
         }
      }
   }
   catch (const std::bad_alloc&)
   {
      ERROR_SET(err, nomem);
   }

exit:
   return r;
}

dns::Record *
dns::MessageWriter::AddRecord(Record *&ptr, std::vector<Record> &vec, I16 &count, uint16_t payload, error *err)
{
   Record *r = nullptr;
   auto oldAttrs = rattrs.data();

   if (vec.size() == 0xffff)
      ERROR_SET(err, unknown, "Too many records");

   try
   {
      vec.resize(vec.size() + 1);
      r = &vec[vec.size()-1];
      auto oldSize = rattrs.size();
      rattrs.resize(oldSize + offsetof(RecordAttrs, Data) + payload);
      r->Attrs = (RecordAttrs*)((char*)rattrs.data() + oldSize);
      r->Attrs->Length.Put(payload);
      r->Attrs = (RecordAttrs*)((char*)oldAttrs + oldSize);
   }
   catch (const std::bad_alloc&)
   {
      if (r)
      {
         vec.resize(vec.size() - 1);
         r = nullptr;
      }
      ERROR_SET(err, nomem);
   }

   // If the attrs vector moved, we need to patch the old pointers.
   //
   if (oldAttrs != rattrs.data())
   {
      for (auto rlist : {&answerReqs, &authorityReqs, &additlRecs})
      {
         for (auto &r : *rlist)
         {
            r.Attrs = (RecordAttrs*)(rattrs.data() + ((char*)r.Attrs - oldAttrs));
         }
      }
   }

   count.Put(vec.size());
   ptr = vec.data();
   r = &vec[vec.size()-1];
exit:
   return r;
}

dns::Question *
dns::MessageWriter::AddQuestion(error *err)
{
   Question *r = nullptr;
   auto oldAttrs = qattrs.data();
   auto &vec = Questions;
   auto &count = Header->QuestionCount;

   if (vec.size() == 0xffff)
      ERROR_SET(err, unknown, "Too many records");

   try
   {
      vec.resize(vec.size() + 1);
      r = &vec[vec.size()-1];
      qattrs.resize(qattrs.size() + 1);
      r->Attrs = oldAttrs + qattrs.size() - 1;
   }
   catch (const std::bad_alloc&)
   {
      if (r)
      {
         vec.resize(vec.size() - 1);
         r = nullptr;
      }
      ERROR_SET(err, nomem);
   }

   if (oldAttrs != qattrs.data())
   {
      for (auto &r : Questions)
      {
         r.Attrs = qattrs.data() + (r.Attrs - oldAttrs);
      }
   }

   count.Put(vec.size());
   r = &vec[vec.size()-1];
exit:
   return r;
}
