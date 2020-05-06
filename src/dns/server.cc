/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#if 1 // XXX
#include <pollster/socket.h>
#endif

#include <dnsserver.h>
#include <dnsmsg.h>

#include <common/logger.h>

void
dns::Server::HandleMessage(
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
      map.OnResponse(msg.Header->Id.Get(), addr, buf, len, msg, err);
      return;
   }

   {
      char msgbuf[4096];
      log_printf("Request:\n%s", msg.Describe(msgbuf, sizeof(msgbuf)));
   }

   // Several DNS servers reject more than one question per packet.
   //
   if (msg.Header->QuestionCount.Get() != 1)
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

#if 1
   {
      struct sockaddr_in in = {0};
      pollster::sockaddr_set_af(&in);
      in.sin_addr.s_addr = 0x08080808U;
      in.sin_port = htons(53);
      SendUdp(
         (struct sockaddr*)&in,
         buf,
         len,
         &msg,
         [] (const void *buf,
             size_t len,
             Message &msg,
             error *err) -> void
         {
            char msgbuf[4096];
            log_printf("Response:\n%s", msg.Describe(msgbuf, sizeof(msgbuf)));
         },
         err
      );
      ERROR_CHECK(err);
   }
#endif

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
