/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsmsg.h>
#include <stdio.h>
#include <stdarg.h>

static inline
uint16_t
read16(const void *pv)
{
   auto p = (const unsigned char*)pv;
   return p[1] | (((uint16_t)*p) << 8);
}

static inline
uint32_t
read32(const void *pv)
{
   auto p = (const unsigned char*)pv;
   return 
          (((uint32_t)*p) << 24) |
          (((uint32_t)p[1]) << 16) |
          (((uint32_t)p[2]) << 8) |
          p[3];
}

uint16_t
dns::I16::Get() const
{
   return read16(&value);
}

uint32_t
dns::I32::Get() const
{
   return read32(&value);
}

int
dns::ParseLabel(
   const void *base,
   size_t baselen,
   const void *data,
   std::string &str,
   error *err
)
{
   ptrdiff_t offset = (const char *)data - (const char*)base;
   size_t inBuffer = 0;
   int r = 0;
   size_t len = 0;
   bool sawPointer = false;

   str.resize(0);

retry:
   if (offset >= baselen)
      ERROR_SET(err, unknown, "out of bounds");

   inBuffer = baselen - offset;
retryPostOffset:
   len = *(unsigned char*)data;

   if (0xc0 & len)
   {
      if ((0xc0 & len) != 0xc0)
         ERROR_SET(err, unknown, "rfc1035 defines this case as reserved for future use");

      if (inBuffer < 2)
         ERROR_SET(err, unknown, "out of bounds");

      if (!sawPointer)
         r += 2;
      sawPointer = true;

      offset = read16(data) & ~0xc000U;
      data = (const char*)base + offset;
      goto retry;
   }
   else if (!len)
   {
      if (!sawPointer)
         r = 1;
   }
   else if (inBuffer < len+1)
      ERROR_SET(err, unknown, "out of bounds");
   else
   {
      if (!sawPointer)
         r += len + 1;

      inBuffer--;
      auto p = (const char*)data + 1;

      try
      {
         str.append(p, p+len);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      p += len;
      inBuffer -= len; 
      data = p;
  
      if (inBuffer)
      {
         if (*p)
         {
            try
            {
               str.push_back('.');
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }
            goto retryPostOffset;
         }
         if (!sawPointer)
            r++;
      }
   }

exit:
   if (ERROR_FAILED(err))
      r = 0;
   return r;
}

const dns::QuestionAttrs *
dns::ParseQuestion(
   const void *base,
   size_t baselen,
   const void *data,
   std::string &name,
   error *err
)
{
   const dns::QuestionAttrs *rec = nullptr;
   ptrdiff_t offset;

   data = (const char*)data + dns::ParseLabel(base, baselen, data, name, err);
   ERROR_CHECK(err);

   rec = (const QuestionAttrs*)data;
   offset = (const char*)rec - (const char *)base;

   if (offset + sizeof(*rec) > baselen)
      ERROR_SET(err, unknown, "out of bounds");

exit:
   if (ERROR_FAILED(err))
   {
      rec = nullptr;
      name.resize(0);
   }
   return rec;
}

const dns::RecordAttrs *
dns::ParseRecord(
   const void *base,
   size_t baselen,
   const void *data,
   std::string &name,
   error *err
)
{
   const dns::RecordAttrs *rec = nullptr;

   ptrdiff_t offset = 0;

   data = (const char*)data + dns::ParseLabel(base, baselen, data, name, err);
   ERROR_CHECK(err);

   rec = (const RecordAttrs*)data;
   offset = (rec->Data - (const char*)base);

   if (offset > baselen ||
       offset + rec->Length.Get() > baselen)
      ERROR_SET(err, unknown, "out of bounds");

exit:
   if (ERROR_FAILED(err))
   {
      rec = nullptr;
      name.resize(0);
   }
   return rec;
}

void
dns::ParseMessage(
   const void *buf,
   size_t len,
   dns::Message *m,
   error *err
)
{
   auto p = (char*)buf;

   if (len < sizeof(m->Header))
   {
      ERROR_SET(err, unknown, "out of bounds");
   }

   m->Header = (MessageHeader*)buf;
   p += sizeof(*m->Header);

   for (int n = m->Header->QuestionCount.Get(); n--; )
   {
      Question q;
      q.Attrs = (QuestionAttrs*)ParseQuestion(buf, len, p, q.Name, err);
      ERROR_CHECK(err);

      p = (char*)q.Attrs + sizeof(*q.Attrs);

      try
      {
         m->Questions.push_back(std::move(q));
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   }

   for (auto &c : {m->Header->AnswerCount, m->Header->AuthorityNameCount, m->Header->AdditionalRecordCount})
   {
      for (int n = c.Get(); n--; )
      {
         Record r;
         r.Attrs = (RecordAttrs*)ParseRecord(buf, len, p, r.Name, err);
         ERROR_CHECK(err);

         p = (char*)r.Attrs->Data + r.Attrs->Length.Get();

         try
         {
            m->Records.push_back(std::move(r));
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      }
   }

   m->Answers = m->Records.data();
   m->AuthorityNames = m->Answers + m->Header->AnswerCount.Get();
   m->AdditionalRecords = m->AuthorityNames + m->Header->AuthorityNameCount.Get();
   if (!m->Header->AnswerCount.Get())
      m->Answers = nullptr;
   if (!m->Header->AuthorityNameCount.Get())
      m->AuthorityNames = nullptr;
   if (!m->Header->AdditionalRecordCount.Get())
      m->AdditionalRecords = nullptr;

exit:;
}

#if defined(__clang__) && \
    __clang_major__ < 7 || (__clang_major__ == 7 && __clang_minor__ == 3)
#define PRINTF_CLOSURE_HACK
// This was previously a closure, but 7.3.0 on Mac was rejecting varargs closures with:
// error: 'va_start' used in function with fixed args
static void
append_printf_helper(char *&cur, size_t &avail, const char *fmt, ...)
{
   if (avail <= 1)
      return;

   va_list ap;
   va_start(ap, fmt);
   vsnprintf(cur, avail, fmt, ap);
   va_end(ap);

   auto l = strlen(cur);
   cur += l;
   avail -= l;
}
#define append_printf(FMT, ...) append_printf_helper(cur, avail, FMT, ##__VA_ARGS__)
#endif

const char *
dns::Message::Describe(char *buf, size_t len)
{
   char *cur = buf;
   size_t avail = len;
   const auto &msg = *this;

#ifndef PRINTF_CLOSURE_HACK
   auto append_printf = [&cur, &avail] (const char *fmt, ...) -> void
   {
      if (avail <= 1)
         return;

      va_list ap;
      va_start(ap, fmt);
      vsnprintf(cur, avail, fmt, ap);
      va_end(ap);

      auto l = strlen(cur);
      cur += l;
      avail -= l;
   };
#endif

   append_printf(
      "request ID:          %.4hx\n"
      "response:            %d\n"
      "opcode:              %d\n"
      "authoritative:       %d\n"
      "truncated:           %d\n"
      "recursion desired:   %d\n"
      "recursion available: %d\n"
      ,
      msg.Header->Id.Get(),
      msg.Header->Response,
      msg.Header->Opcode,
      msg.Header->Authoritative,
      msg.Header->Truncated,
      msg.Header->RecursionDesired,
      msg.Header->RecursionAvailable
   );

   append_printf("response code:       ");
   {
      const char *p = ResponseCodeToString(msg.Header->ResponseCode);
      if (p)
         append_printf("%s", p);
      else
         append_printf("%d", msg.Header->ResponseCode);
      append_printf("\n");
   }

   for (auto &q : msg.Questions)
   {
      const char *p;

      append_printf("Question: [%s]", q.Name.c_str());

      append_printf(", type ");
      p = TypeToString(q.Attrs->Type.Get());
      if (p)
         append_printf("%s", p);
      else
         append_printf("%.4x", q.Attrs->Type.Get());

      append_printf(", class ");
      p = ClassToString(q.Attrs->Class.Get());
      if (p)
         append_printf("%s", p);
      else
         append_printf("%.4x", q.Attrs->Class.Get());

      append_printf("\n");
   }

   auto doRec =
#ifndef PRINTF_CLOSURE_HACK
   [&append_printf]
#else
   [&cur, &avail]
#endif
   (const char *label, const dns::Record *rec, const dns::I16 &nrec) -> void
   {
      for (auto end = rec+nrec.Get(); rec < end; ++rec)
      {
         const char *p;

         append_printf("%s: [%s]", label, rec->Name.c_str()); //, type %d, ttl %d, %d bytes",

         append_printf(", type ");
         p = TypeToString(rec->Attrs->Type.Get());
         if (p)
            append_printf("%s", p);
         else
            append_printf("%.4x", rec->Attrs->Type.Get());

         append_printf(", class ");
         p = ClassToString(rec->Attrs->Class.Get());
         if (p)
            append_printf("%s", p);
         else
            append_printf("%.4x", rec->Attrs->Class.Get());

         append_printf(
            ", ttl %d, %d bytes\n",
            rec->Attrs->Ttl.Get(),
            rec->Attrs->Length.Get()
         );
      }
   };
   doRec("Answer", msg.Answers, msg.Header->AnswerCount);
   doRec("Authority name", msg.AuthorityNames, msg.Header->AuthorityNameCount);
   doRec("Additional record", msg.AdditionalRecords, msg.Header->AdditionalRecordCount);

   while (avail < len && buf[len-avail-1] == '\n')
   {
      buf[len - avail - 1] = 0;
      ++avail;
   }

   return buf;
}

#undef append_printf

const char *
dns::TypeToString(uint16_t type)
{
   switch ((Type)type)
   {
#define TYPE(X) case Type::X: return #X
      TYPE(A);
      TYPE(NS);
      TYPE(MD);
      TYPE(MF);
      TYPE(CNAME);
      TYPE(SOA);
      TYPE(MB);
      TYPE(MG);
      TYPE(MR);
      case Type::NullRR: return "NULL";
      TYPE(WKS);
      TYPE(PTR);
      TYPE(HINFO);
      TYPE(MINFO);
      TYPE(MX);
      TYPE(TXT);
      TYPE(AAAA);
#undef TYPE
   }

   switch ((QType)type)
   {
#define TYPE(X) case QType::X: return #X
      TYPE(AXFR);
      TYPE(MAILA);
      TYPE(MAILB);
      TYPE(ALL);
#undef TYPE
   }

   return nullptr;
}

const char *
dns::ClassToString(uint16_t cl)
{
   switch ((Class)cl)
   {
#define CLASS(X) case Class::X: return #X
      CLASS(IN);
      CLASS(CS);
      CLASS(CH);
      CLASS(HS);
      CLASS(Any);
#undef CLASS
   }

   return nullptr;
}

const char *
dns::ResponseCodeToString(unsigned char response)
{
   switch ((ResponseCode)response)
   {
#define CODE(X) case ResponseCode::X: return #X
      CODE(NoError);
      CODE(FormatError);
      CODE(ServerFailure);
      CODE(NameError);
      CODE(NotImplemented);
      CODE(Refused);
#undef CODE
   }
   return nullptr;
}