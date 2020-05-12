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
#include <vector>

#include <common/c++/handle.h>
#include <common/error.h>

#include <dnsreqmap.h>

namespace dns {

struct Message;

class Server : public std::enable_shared_from_this<Server>
{
public:
   void
   StartUdp(int af, error *err);

   void
   StartTcp(error *err);

   void
   AddForwardServer(const struct sockaddr *sa, error *err);
private:
   std::shared_ptr<common::SocketHandle> udpSocket, udp6Socket;
   ResponseMap udpResp, udp6Resp;
   std::vector<std::vector<char>> forwardServers;

   void
   HandleMessage(
      void *buf, size_t len,
      const struct sockaddr *addr,
      ResponseMap &map,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
   );

   void
   SendUdp(
      const std::shared_ptr<common::SocketHandle> &fd,
      const struct sockaddr *addr,
      const void *buf,
      size_t len,
      error *err
   );

   void
   SendUdp(
      const struct sockaddr *addr,
      const void *buf,
      size_t len,
      const Message *msg,
      const ResponseMap::Callback &cb,
      error *err
   );
};

} // end namespace

#endif
