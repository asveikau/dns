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

class Server
{
   std::shared_ptr<common::SocketHandle> udpSocket, udp6Socket;

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
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
  );
public:
   void
   StartUdp(int af, error *err);

   void
   StartTcp(error *err);

   void
   SendUdp(const struct sockaddr *addr, const void *buf, size_t len, error *err);
};

} // end namespace

#endif
