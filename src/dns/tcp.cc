/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/sockapi.h>
#include <dnsserver.h>
#include <dnsproto.h>
#include <dnsmsg.h>

#include <vector>

namespace {

void
WriteTcp(const std::shared_ptr<pollster::StreamSocket> &fd, const void *buf, size_t len, error *err)
{
   if (fd.get())
   {
      if (len > 65535)
      {
         auto hdr = (dns::MessageHeader*)buf;
         hdr->Truncated = 1;
         len = 65535;
      }
      unsigned char lenpkt[] =
      {
         (unsigned char)(len >> 8), (unsigned char)len
      };
      fd->Write(lenpkt, sizeof(lenpkt));
      fd->Write(buf, len);
   }
}

template <typename OnClose>
void
CreateTcp(
   const std::weak_ptr<dns::Server> &weak,
   const std::shared_ptr<pollster::StreamSocket> &fd,
   dns::ResponseMap **map,
   dns::MessageMode mode,
   const OnClose &onClose,
   error *err
)
{
   struct State
   {
      std::weak_ptr<dns::Server> srv;
      std::shared_ptr<pollster::StreamSocket> fd;
      std::vector<char> bufferedBytes;
      dns::ResponseMap map;
   };
   std::shared_ptr<State> state;
   try
   {
      state = std::make_shared<State>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   fd->on_recv = [state, mode] (const void *buf, size_t len, error *err) -> void
   {
      bool heap = false;

      if (!len)
         return;

      if (state->bufferedBytes.size())
      {
         try
         {
            state->bufferedBytes.insert(state->bufferedBytes.end(), (char*)buf, (char*)buf + len);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }

         heap = true;
         buf = state->bufferedBytes.data();
         len = state->bufferedBytes.size();
      }

      for (;;)
      {
         if (len < 2)
            break;

         auto p = (const unsigned char*)buf;;
         uint16_t plen = p[1] | (((uint16_t)*p) << 8);
         if (len < 2 + plen)
            break;

         auto srv = state->srv.lock();
         if (!srv.get())
            break;

         srv->HandleMessage(
            mode,
            (char*)buf+2, plen,
            nullptr,
            state->map,
            [state] (const void *buf, size_t len, error *err) -> void
            {
               WriteTcp(state->fd, buf, len, err);
            },
            err
         );
         ERROR_CHECK(err);

         size_t r = 2 + (size_t)plen;
         buf = p + r;
         len -= r;
      }

      if (len && !heap)
      {
         try
         {
            state->bufferedBytes.insert(state->bufferedBytes.end(), (char*)buf, (char*)buf+len);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
      }
      else
      {
         auto begin = state->bufferedBytes.begin();
         state->bufferedBytes.erase(begin, begin + (state->bufferedBytes.size() - len));
      }
   exit:;
   };

   fd->on_closed = [state, onClose] (error *err) -> void
   {
      onClose(state->map);
      state->fd.reset();
   };

   state->fd = fd;
   state->srv = weak;
   if (map)
      *map = &state->map;
exit:;
}

} // end namespace

void
dns::Server::StartTcp(error *err)
{
   static pollster::StreamServer srv;

   if (!srv.on_client)
   {
      std::weak_ptr<Server> weak = shared_from_this();

      srv.on_client = [weak] (const std::shared_ptr<pollster::StreamSocket> &fd, error *err) -> void
      {
         CreateTcp(
            weak,
            fd,
            nullptr,
            MessageMode::Server,
            [] (ResponseMap &map) -> void
            {
            },
            err
         );
         ERROR_CHECK(err);
         exit:;
      };

      srv.AddPort(53, err);
      ERROR_CHECK(err);
   }
exit:;
}

void
dns::Server::SendTcp(
   const std::shared_ptr<ForwardServerState> &state,
   const void *buf,
   size_t len,
   const Message *msg,
   const ResponseMap::Callback &cb,
   error *err
)
{
   if (!state->tcpSocket.get())
   {
      try
      {
         auto fd = std::make_shared<pollster::StreamSocket>();
         CreateTcp(
            shared_from_this(),
            fd,
            &state->tcpMap,
            MessageMode::Client,
            [state] (ResponseMap &map) -> void
            {
               state->tcpSocket.reset();
               state->tcpMap = nullptr;
            },
            err
         );
         ERROR_CHECK(err);
         state->tcpSocket = fd;
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   }
   WriteTcp(state->tcpSocket, buf, len, err);
   ERROR_CHECK(err);
   if (cb)
   {
      Message msgStorage;
      auto &map = *(state->tcpMap);

      if (!msg)
      {
         ParseMessage(buf, len, &msgStorage, err);
         ERROR_CHECK(err);
         msg = &msgStorage;
      }
      if (len < 2)
         ERROR_SET(err, unknown, "Short write");
      map.OnRequest(((MessageHeader*)buf)->Id.Get(), nullptr, *msg, cb, err);
   }
exit:;
}
