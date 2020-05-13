/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsproto.h>
#include <dnsmsg.h>

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

std::vector<char>
dns::MessageWriter::Serialize(error *err)
{
   std::vector<char> r;

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
      r->Attrs = (RecordAttrs*)((char*)oldAttrs + oldSize);
      r->Attrs->Length.Put(payload);
   }
   catch (std::bad_alloc)
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
   catch (std::bad_alloc)
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