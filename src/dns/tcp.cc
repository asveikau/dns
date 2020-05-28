/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/sockapi.h>
#include <dnsserver.h>
#include <dnsproto.h>

#include <vector>

namespace {

template <typename OnRead>
void
CreateTcp(
   const std::weak_ptr<dns::Server> &weak,
   const std::shared_ptr<pollster::StreamSocket> &fd,
   const OnRead &onRead,
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

   fd->on_recv = [state, onRead] (const void *buf, size_t len, error *err) -> void
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

         onRead(srv, state->fd, (char*)p+2, plen, state->map, err);
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

   fd->on_closed = [state] (error *err) -> void
   {
      state->fd.reset();
   };

   state->fd = fd;
   state->srv = weak;
exit:;
}

void
WriteTcp(const std::shared_ptr<pollster::StreamSocket> &fd, const void *buf, size_t len, error *err)
{
   if (fd.get())
   {
      if (len > 65535 && len >= 3)
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
            [] (
               const std::shared_ptr<Server> &srv,
               const std::shared_ptr<pollster::StreamSocket> &fd,
               void *buf,
               size_t len,
               ResponseMap &map,
               error *err
            ) -> void
            {
               std::weak_ptr<pollster::StreamSocket> weakFd = fd;

               srv->HandleMessage(
                  buf, len,
                  nullptr,
                  map,
                  [weakFd] (const void *buf, size_t len, error *err) -> void
                  {
                     auto fd = weakFd.lock();
                     WriteTcp(fd, buf, len, err);
                  },
                  err
               );
               ERROR_CHECK(err);
            exit:;
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
