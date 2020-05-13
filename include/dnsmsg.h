/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef dnsmsg_h_
#define dnsmsg_h_

#include <string>
#include <vector>

#include <common/error.h>

#include "dnsproto.h"

namespace dns
{

struct Question
{
   std::string Name;
   QuestionAttrs *Attrs;
};

struct Record
{
   std::string Name;
   RecordAttrs *Attrs;
};

struct Message
{
   MessageHeader *Header;
   std::vector<Question> Questions;
   Record *Answers, *AuthorityNames, *AdditionalRecords;
   std::vector<Record> Records;

   Message() : Answers(nullptr), AuthorityNames(nullptr), AdditionalRecords(nullptr)
   {
   }

   const char *
   Describe(char *buf, size_t len);
};

class MessageWriter : public Message
{
   MessageHeader headerStorage;
   std::vector<QuestionAttrs> qattrs;
   std::vector<char> rattrs;
   std::vector<Record> answerReqs, authorityReqs, additlRecs;

   Record *
   AddRecord(Record *&ptr, std::vector<Record> &vec, I16 &count, uint16_t payload, error *err);

public:
   MessageWriter()
   {
      Header = &headerStorage;
   }

   std::vector<char>
   Serialize(error *err);

   Question *
   AddQuestion(error *err);

   Record *
   AddAnswer(uint16_t payload, error *err)
   {
      return AddRecord(Answers, answerReqs, Header->AnswerCount, payload, err);
   }

   Record *
   AddAuthority(uint16_t payload, error *err)
   {
      return AddRecord(AuthorityNames, authorityReqs, Header->AuthorityNameCount, payload, err);
   }

   Record *
   AddAdditional(uint16_t payload, error *err)
   {
      return AddRecord(AdditionalRecords, additlRecs, Header->AdditionalRecordCount, payload, err);
   }
};

void
ParseMessage(
   const void *buf,
   size_t len,
   Message *m,
   error *err
);

const char *TypeToString(uint16_t type);
const char *ClassToString(uint16_t cl);
const char *ResponseCodeToString(unsigned char response);

// returns the offset to the piece after the string
int
ParseLabel(
   const void *base,     // start message
   size_t baselen,       // total message length
   const void *data,     // current offset
   std::string &output,
   error *err
);

const RecordAttrs *
ParseRecord(
   const void *base,
   size_t baselen,
   const void *data,
   std::string &name,
   error *err
);

const QuestionAttrs *
ParseQuestion(
   const void *base,
   size_t baselen,
   const void *data,
   std::string &name,
   error *err
);

} // end namespace

#endif
