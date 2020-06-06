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
#include <config.h>

namespace dns {

struct Message;

enum class MessageMode
{
   Client = (1),
   Server = (1<<1),
   Both   = Client | Server
};

enum class Protocol
{
   Plaintext,
   DnsOverTls,
};

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
   Initialize(error *err);

   void
   AttachConfig(ConfigFileMap& map, error *err);

   void
   StartUdp(int af, error *err)
   {
      StartUdp(af, MessageMode::Both, err);
   }

   void
   StartTcp(error *err);

   void
   AddForwardServer(
      const char *hostname,
      const struct sockaddr *sa,
      Protocol proto,
      error *err
   );

   void
   ClearForwardServers();

   // XXX this was private before, and makes more sense like that.
   void
   HandleMessage(
      MessageMode mode,
      void *buf, size_t len,
      const struct sockaddr *addr,
      ResponseMap &map,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
   );

private:

   struct ForwardServerState
   {
      std::vector<char> sockaddr;
      std::shared_ptr<pollster::StreamSocket> tcpSocket;
      ResponseMap *tcpMap;
      Protocol proto;
      std::string hostname;

      ForwardServerState() : tcpMap(nullptr), proto(Protocol::Plaintext) {}
   };

   struct ForwardClientState : public std::enable_shared_from_this<ForwardClientState>
   {
      std::vector<std::function<void(const void *, size_t, error *)>> reply;
      std::vector<std::function<void()>> cancel;
      std::vector<char> request;
      bool udpExhausted;
      int idx;
      int timeoutIdx;

      ForwardClientState() : udpExhausted(false), idx(0), timeoutIdx(0) {}

      void
      Reply(const void *buf, size_t len);

      void
      Cancel();
   };

   std::shared_ptr<common::SocketHandle> udpSocket, udp6Socket;
   ResponseMap udpResp, udp6Resp;
   std::vector<std::shared_ptr<ForwardServerState>> forwardServers;
   RequestMap<bool> udpDeDupe;
   RequestMap<std::shared_ptr<ForwardClientState>> forwardReqs;
   struct rng_state *rng;
   std::string searchPath;

   void
   TryForwardPacket(
      const struct sockaddr *addr,
      void *buf, size_t len,
      const Message &msg,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err      
   );

   void
   TryForwardPacket(const std::shared_ptr<ForwardClientState> &state, error *err);

   bool
   TryCache(
      const Message &msg,
      const std::function<void(const void *, size_t, error *)> &reply
   );

   void
   CacheReply(const void *buf, size_t len);

   void
   SendUdp(
      const std::shared_ptr<ForwardServerState> &state,
      const void *buf,
      size_t len,
      const Message *msg,
      const ResponseMap::Callback &cb,
      std::function<void()> *cancel,
      error *err
   );

   void
   SendTcp(
      const std::shared_ptr<ForwardServerState> &state,
      const void *buf,
      size_t len,
      const Message *msg,
      const ResponseMap::Callback &cb,
      std::function<void()> *cancel,
      error *err
   );

   void
   StartUdp(int af, MessageMode mode, error *err);
};

} // end namespace

#endif
