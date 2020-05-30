/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <dnsserver.h>
#include <dnsmsg.h>

#include <string.h>

void
dns::Server::TryForwardPacket(
   const struct sockaddr *addr,
   void *buf, size_t len,
   const Message &msg,
   const std::function<void(const void *, size_t, error *)> &innerReply,
   error *err      
)
{
   uint16_t originalId;

   if (addr && udpDeDupe.Lookup(addr, msg))
      goto exit;

   if (!forwardServers.size())
      ERROR_SET(err, unknown, "no forward servers");

   memcpy(&originalId, &msg.Header->Id, sizeof(msg.Header->Id));

   auto reply = [originalId, innerReply] (const void *buf, size_t len, error *err) -> void
   {
      uint16_t id;
      auto hdr = (MessageHeader*)buf;
      memcpy(&id, &hdr->Id, sizeof(hdr->Id));
      memcpy(&hdr->Id, &originalId, sizeof(hdr->Id));
      innerReply(buf, len, err);
      memcpy(&hdr->Id, &id, sizeof(hdr->Id));
   };

   if (!rng)
   {
      rng_init(&rng, err);
      ERROR_CHECK(err);
   }

   rng_generate(rng, &msg.Header->Id, sizeof(msg.Header->Id), err);
   ERROR_CHECK(err);

   // TODO
exit:;
}

void
dns::Server::AddForwardServer(
   const struct sockaddr *sa,
   Protocol proto,
   error *err
)
{
   try
   {
      auto state = std::make_shared<ForwardServerState>();

      state->proto = proto;

      auto &vec = state->sockaddr;
      auto sap = (const char*)sa;
      vec.insert(vec.end(), sap, sap+pollster::socklen(sa));

      forwardServers.push_back(std::move(state));
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

void
dns::Server::ClearForwardServers()
{
   forwardServers.resize(0);
}
