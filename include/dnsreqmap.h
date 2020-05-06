/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef dns_reqmap_h_
#define dns_reqmap_h_

#include <map>
#include <vector>

struct sockaddr;

namespace dns {

struct Message;

class ResponseMap
{
public:
   void
   OnResponse(
      uint16_t id,
      const struct sockaddr *,
      const void *buf,
      size_t len,
      Message &msg,
      error *err
   );

   typedef std::function<void(
      const void *buf,
      size_t len,
      Message &msg,
      error *err
   )> Callback;

   void
   OnRequest(
      uint16_t id,
      const struct sockaddr *addr,
      const Callback &cb,
      error *err
   );

private:
   struct ClientData
   {
      Callback cb;
      std::vector<char> sockaddr;
   };
   std::map<uint16_t, ClientData> map;

   ClientData *
   Lookup(uint16_t id, const struct sockaddr *addr);
};

} // end namespace

#endif