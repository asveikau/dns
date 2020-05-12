/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

//
// Structures and constants here should come directly out of RFC1035.
//

#ifndef dnsproto_h_
#define dnsproto_h_ 1

#include <stdint.h>

#if defined(_WINDOWS)
#undef IN
#endif

namespace dns {
#pragma pack(push, 1)

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4200) // C99 flexible array member
#endif

class I16
{
   uint16_t value;
public:
   uint16_t
   Get() const;

   void
   Put(uint16_t value);
};

class I32
{
   uint32_t value;
public:
   uint32_t
   Get() const;

   void
   Put(uint32_t value);
};

struct MessageHeader
{
   I16 Id;
   unsigned char RecursionDesired : 1;
   unsigned char Truncated : 1;
   unsigned char Authoritative : 1;
   unsigned char Opcode : 4;
   unsigned char Response : 1;
   unsigned char ResponseCode : 4;
   unsigned char Reserved : 3;
   unsigned char RecursionAvailable : 1;
   I16 QuestionCount;
   I16 AnswerCount;
   I16 AuthorityNameCount;
   I16 AdditionalRecordCount;

   MessageHeader() { memset(this, 0, sizeof(*this)); }
};

struct RecordAttrs
{
   I16 Type;
   I16 Class;
   I32 Ttl;
   I16 Length;
   char Data[];
};

struct QuestionAttrs
{
   I16 Type;
   I16 Class;
};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#pragma pack(pop)

enum class Type
{
   A       = 1,
   NS      = 2,
   MD      = 3,
   MF      = 4,
   CNAME   = 5,
   SOA     = 6,
   MB      = 7,
   MG      = 8,
   MR      = 9,
   NullRR  = 10,
   WKS     = 11,
   PTR     = 12,
   HINFO   = 13,
   MINFO   = 14,
   MX      = 15,
   TXT     = 16,
};

enum class QType
{
   AXFR  = 252,
   MAILB = 253,
   MAILA = 254,
   ALL   = 255,
};

enum class Class
{
   IN = 1,

   // Wow, these are highly relevant from this RFC from 1987 ...
   //
   CS = 2,
   CH = 3,
   HS = 4,

   Any = 255,
};

enum class ResponseCode
{
   NoError = 0,
   FormatError = 1,
   ServerFailure = 2,
   NameError = 3,
   NotImplemented = 4,
   Refused = 5,
};

} // end namespace

#endif
