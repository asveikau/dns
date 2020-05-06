/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/pollster.h>

#include <dnsserver.h>
#include <dnsproto.h>

using pollster::sendrecv_retval;

void
dns::Server::StartUdp(int af, error *err)
{
   std::shared_ptr<common::SocketHandle> fd;
   common::Pointer<pollster::waiter> loop;
   common::Pointer<pollster::socket_event> sev;
   union u_addr
   {
      struct sockaddr sa;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
   };
   u_addr addr;

   memset(&addr, 0, sizeof(addr));

   pollster::get_common_queue(loop.GetAddressOf(), err);
   ERROR_CHECK(err);

   try
   {
      fd = std::make_shared<common::SocketHandle>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   *fd = socket(af, SOCK_DGRAM, 0);
   if (!fd->Valid())
      ERROR_SET(err, socket);

   pollster::sockaddr_set_af(&addr.sa, af);

   switch (af)
   {
   case AF_INET:
      addr.sin.sin_port = htons(53);
      break;
   case AF_INET6:
      addr.sin6.sin6_port = htons(53);
      break;
   }

   if (bind(fd->Get(), &addr.sa, pollster::socklen(&addr.sa)))
      ERROR_SET(err, socket);

   set_nonblock(fd->Get(), true, err);
   ERROR_CHECK(err);

   switch (af)
   {
   case AF_INET:
      udpSocket = fd;
      break;
   case AF_INET6:
      udp6Socket = fd;
   }

   loop->add_socket(
      fd,
      false,
      [fd, this] (pollster::socket_event *sev, error *err) -> void
      {
         sev->on_signal = [fd, this] (error *err) -> void
         {
            char buf[512];
            u_addr addr;
            #if defined(_WINDOWS)
            int
            #else
            socklen_t
            #endif
            addrlen = sizeof(addr);
            sendrecv_retval r;

            while ((r = recvfrom(fd->Get(), buf, sizeof(buf), 0, &addr.sa, &addrlen)) > 0)
            {
               HandleMessage(
                  buf, r,
                  [fd, addr, this] (const void *buf, size_t len, error *err) -> void
                  {
                     SendUdp(fd, &addr.sa, buf, len, err);
                  },
                  err
               );
               ERROR_CHECK(err);
            }
         exit:;
         };
      },
      sev.GetAddressOf(),
      err
   );
exit:;
}

void
dns::Server::SendUdp(
   const std::shared_ptr<common::SocketHandle> &fd,
   const struct sockaddr *addr,
   const void *buf,
   size_t len,
   error *err
)
{
   sendrecv_retval r = 0;

   if (len > 512)
   {
      auto hdr = (MessageHeader*)buf;
      hdr->Truncated = 1;
      len = 512;
   }

   if ((r = sendto(fd->Get(), buf, len, 0, addr, pollster::socklen(addr))) < 0)
   {
      ERROR_SET(err, socket);
   }
exit:;
}

void
dns::Server::SendUdp(
   const struct sockaddr *addr,
   const void *buf,
   size_t len,
   error *err
)
{
   std::shared_ptr<common::SocketHandle> *fdp = nullptr;
   switch (addr->sa_family)
   {
   case AF_INET:
      fdp = &udpSocket;
      break;
   case AF_INET6:
      fdp = &udp6Socket;
      break;
   default:
      error_set_unknown(err, "Invalid family");
      return;
   }
   auto &fd = *fdp;
   if (!fd->Valid())
      ERROR_SET(err, unknown, "TODO: set up new socket");
   SendUdp(fd, addr, buf, len, err);
exit:;
}