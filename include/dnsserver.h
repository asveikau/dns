/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef dnsserver_h_
#define dnsserver_h_ 1

#include <stddef.h>
#include <functional>
#include <memory>

#include <common/c++/handle.h>
#include <common/error.h>

struct sockaddr;

namespace dns {

struct Message;

struct ResponseMap
{
   void
   OnResponse(
      uint16_t id,
      const struct sockaddr *,
      const void *buf,
      size_t len,
      Message &msg,
      error *err
   ) {}

   void
   OnNoResponse(uint16_t id, const struct sockaddr *) {}

   typedef std::function<void(
      const void *buf,
      size_t len,
      Message &msg,
      error *err)
   > Callback;

   void
   OnRequest(
      uint16_t id,
      const struct sockaddr *addr,
      const Callback &cb,
      error *err
   ) {}
};

class Server
{
   std::shared_ptr<common::SocketHandle> udpSocket, udp6Socket;
   ResponseMap udpResp, udp6Resp;

   void
   SendUdp(
      const std::shared_ptr<common::SocketHandle> &fd,
      const struct sockaddr *addr,
      const void *buf,
      size_t len,
      error *err
   );
protected:
   void
   HandleMessage(
      void *buf, size_t len,
      const struct sockaddr *addr,
      ResponseMap &map,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
  );
public:
   void
   StartUdp(int af, error *err);

   void
   StartTcp(error *err);

   void
   SendUdp(const struct sockaddr *addr, const void *buf, size_t len, const ResponseMap::Callback &cb, error *err);
};

} // end namespace

#endif
