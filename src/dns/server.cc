/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>

#include <dnsserver.h>
#include <dnsmsg.h>

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

   // Several DNS servers reject more than one question per packet.
   //
   if (msg.Header->QuestionCount.Get() != 1)
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

void
dns::Server::AddForwardServer(
   const struct sockaddr *sa,
   error *err
)
{
   try
   {
      std::vector<char> vec;
      auto sap = (const char*)sa;
      vec.insert(vec.end(), sap, sap+pollster::socklen(sa));
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}