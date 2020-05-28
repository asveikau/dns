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
#include <common/crypto/rng.h>

#include <pollster/sockapi.h>

#include <dnsreqmap.h>

namespace dns {

struct Message;

class Server : public std::enable_shared_from_this<Server>
{
public:
   Server() : rng(nullptr) {}
   Server(const Server&) = delete;
   ~Server()
   {
      if (rng) rng_close(rng);
   }

   void
   StartUdp(int af, error *err);

   void
   StartTcp(error *err);

   void
   AddForwardServer(const struct sockaddr *sa, error *err);

   void
   ClearForwardServers();
private:

   struct ForwardServerState
   {
      std::vector<char> sockaddr;
      std::shared_ptr<pollster::StreamSocket> tcpSocket;
      ResponseMap *tcpMap;

      ForwardServerState() : tcpMap(nullptr) {}
   };

   std::shared_ptr<common::SocketHandle> udpSocket, udp6Socket;
   ResponseMap udpResp, udp6Resp;
   std::vector<std::shared_ptr<ForwardServerState>> forwardServers;
   struct rng_state *rng;

   void
   HandleMessage(
      void *buf, size_t len,
      const struct sockaddr *addr,
      ResponseMap &map,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
   );

   void
   TryForwardPacket(
      void *buf, size_t len,
      const Message &msg,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err      
   );

   void
   SendUdp(
      const std::shared_ptr<ForwardServerState> &state,
      const void *buf,
      size_t len,
      const Message *msg,
      const ResponseMap::Callback &cb,
      error *err
   );

   void
   SendTcp(
      const std::shared_ptr<ForwardServerState> &state,
      const void *buf,
      size_t len,
      const Message *msg,
      const ResponseMap::Callback &cb,
      error *err
   );
};

} // end namespace

#endif
