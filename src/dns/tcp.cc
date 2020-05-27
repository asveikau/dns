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

void
dns::Server::StartTcp(error *err)
{
   static pollster::StreamServer srv;

   if (!srv.on_client)
   {
      std::weak_ptr<Server> weak = shared_from_this();

      srv.on_client = [weak] (const std::shared_ptr<pollster::StreamSocket> &fd, error *err) -> void
      {
         struct State
         {
            std::weak_ptr<dns::Server> srv;
            std::shared_ptr<pollster::StreamSocket> fd;
            std::vector<char> bufferedBytes;
            ResponseMap map;
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

         fd->on_recv = [state] (const void *buf, size_t len, error *err) -> void
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
                  (char*)p+2, plen,
                  nullptr,
                  state->map,
                  [state] (const void *buf, size_t len, error *err) -> void
                  {
                     auto fd = state->fd;
                     if (!fd.get())
                        return;
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

         fd->on_closed = [state] (error *err) -> void
         {
            state->fd.reset();
         };

         state->fd = fd;
         state->srv = weak;
      exit:;
      };

      srv.AddPort(53, err);
      ERROR_CHECK(err);
   }
exit:;
}
