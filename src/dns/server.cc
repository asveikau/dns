/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsserver.h>
#include <dnsmsg.h>

#include <common/logger.h>

void
dns::Server::HandleMessage(
   void *buf, size_t len,
   const std::function<void(const void *, size_t, error *)> &reply,
   error *err
)
{
   Message msg;
   char msgbuf[4096];
   ResponseCode rc = ResponseCode::ServerFailure;

   ParseMessage(buf, len, &msg, err);
   if (ERROR_FAILED(err))
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

   log_printf("Incoming message:\n%s", msg.Describe(msgbuf, sizeof(msgbuf)));

   // Several DNS servers reject more than one question per packet.
   //
   if (!msg.Header->Response && msg.Header->QuestionCount.Get() != 1)
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }


exit:;
   if (ERROR_FAILED(err))
      goto errorReply;
   return;
errorReply:
   error_clear(err);
   if (len > 2 && (len < 3 || !((MessageHeader*)buf)->Response))
   {
      MessageHeader repl;

      memcpy(&repl.Id, &((MessageHeader*)buf)->Id, sizeof(repl.Id));
      repl.Response = 1;
      repl.ResponseCode = (unsigned)rc;

      reply(&repl, sizeof(repl), err);
      error_clear(err);
   }
}
