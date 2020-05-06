/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <dnsreqmap.h>

#include <string.h>

void
dns::ResponseMap::OnResponse(
   uint16_t id,
   const struct sockaddr *addr,
   const void *buf,
   size_t len,
   Message &msg,
   error *err
)
{
   auto res = Lookup(id, addr);
   if (res)
   {
      auto cb = std::move(res->cb);
      map.erase(id);
      if (cb)
         cb(buf, len, msg, err);
   }
}

void
dns::ResponseMap::OnNoResponse(uint16_t id, const struct sockaddr *addr)
{
   auto res = Lookup(id, addr);
   if (res)
      map.erase(id);
}

dns::ResponseMap::ClientData *
dns::ResponseMap::Lookup(uint16_t id, const struct sockaddr *addr)
{
   auto p = map.find(id);
   if (p == map.end())
      return nullptr;
   auto &res = p->second;
   if ((addr ? pollster::socklen(addr) : 0) != res.sockaddr.size())
      return nullptr;
   if (addr)
   {
#if 0
      if (memcmp(addr, res.sockaddr.data(), res.sockaddr.size()))
#else
      int off = 0;
      size_t len = 0;
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
         return nullptr;
      }
      if (memcmp((const char*)addr+off, res.sockaddr.data()+off, len))
#endif
         return nullptr;
   }
   return &res;
}

void
dns::ResponseMap::OnRequest(
   uint16_t id,
   const struct sockaddr *addr,
   const Callback &cb,
   error *err
)
{
   ClientData state;

   try
   {
      if (addr)
      {
         auto p = (const char *)addr;
         state.sockaddr.insert(state.sockaddr.begin(), p, p+pollster::socklen(addr));
      }
      state.cb = cb;
      map[id] = std::move(state);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}