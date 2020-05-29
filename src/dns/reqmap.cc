/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <dnsreqmap.h>
#include <dnsmsg.h>

#include <string.h>

void
dns::ResponseMap::OnResponse(
   const struct sockaddr *addr,
   const void *buf,
   size_t len,
   Message &msg,
   error *err
)
{
   auto resp = reqs.Lookup(addr, msg);
   if (resp)
   {
      auto cb = std::move(*resp);
      reqs.Remove(msg.Header->Id.Get(), resp);
      if (cb)
         cb(buf, len, msg, err);
   }
}

void
dns::ResponseMap::OnRequest(
   const struct sockaddr *addr,
   const Message &msg,
   const Callback &cb,
   error *err
)
{
   reqs.Insert(addr, msg, cb, err);
}

bool
dns::internal::ParseAddr(const struct sockaddr *addr, int &off, size_t &len)
{
   if (!addr)
   {
   fail:
      len = off = 0;
      return false;
   }
   switch (addr->sa_family)
   {
   case AF_INET:
      off = offsetof(sockaddr_in, sin_addr) + offsetof(in_addr, s_addr);
      len = sizeof(in_addr::s_addr);
      break;
   case AF_INET6:
      off = offsetof(sockaddr_in6, sin6_addr) + offsetof(in6_addr, s6_addr);
      len = sizeof(in6_addr::s6_addr);
      break;
   default:
      goto fail;
   }
   return true;
}

