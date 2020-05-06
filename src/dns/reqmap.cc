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
   if (addr &&
       memcmp(addr, res.sockaddr.data(), res.sockaddr.size()))
      return nullptr;
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