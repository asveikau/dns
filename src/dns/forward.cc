/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <dnsserver.h>
#include <dnsmsg.h>

#include <string.h>

void
dns::Server::TryForwardPacket(const std::shared_ptr<ForwardClientState> &state, error *err)
{
   auto &idx = state->idx;
   std::function<void()> cancel;
   std::weak_ptr<Server> weak = shared_from_this();
   common::Pointer<pollster::waiter> loop;
   common::Pointer<pollster::event> timer;

   if (idx >= forwardServers.size())
   {
      error_set_unknown(err, "No remaining forward servers");
      return;
   }

   auto &server = forwardServers[idx];
   switch (server->proto)
   {
   case Protocol::Plaintext:
      break;
   case Protocol::DnsOverTls:
      state->udpExhausted = true;
      break;
   }

   auto reply = [state, weak] (const void *buf, size_t len) -> void
   {
      state->Reply(buf, len);

      auto rc = weak.lock();
      if (rc.get())
         rc->CacheReply(buf, len);
   };

   auto advance = [state, weak] () -> void
   {
      auto rc = weak.lock();
      if (!rc.get())
         return;
      error errStorage;
      error *err = &errStorage;

      state->idx++;
      state->udpExhausted = false;

      if (state->idx >= rc->forwardServers.size())
      {
         Message msg;
         MessageWriter writer;

         ParseMessage(state->request.data(), state->request.size(), &msg, err);
         ERROR_CHECK(err);

         writer.Header->Response = 1;
         writer.Header->ResponseCode = (unsigned)ResponseCode::ServerFailure;
         writer.Header->RecursionAvailable = 1;

         for (auto q : msg.Questions)
         {
            auto qq = writer.AddQuestion(err);
            ERROR_CHECK(err);
            qq->Name = std::move(q.Name);
            *qq->Attrs = *q.Attrs;
         }

         auto vec = writer.Serialize(err);
         state->Reply(vec.data(), vec.size());
         goto exit;
      }

      rc->TryForwardPacket(state, err);
   exit:;
   };

   rng_generate(rng, state->request.data(), sizeof(dns::MessageHeader::Id), err);
   ERROR_CHECK(err);

   if (!state->udpExhausted)
   {
      SendUdp(
         server,
         state->request.data(),
         state->request.size(),
         nullptr,
         (state->timeoutIdx == 0) ? [reply, weak, state, idx] (const void *buf, size_t len, Message &msg, error *err) -> void
         {
            if (msg.Header->Truncated)
            {
               auto rc = weak.lock();
               if (!rc.get())
                  return;

               state->idx = idx;
               state->udpExhausted = true;
               rc->TryForwardPacket(state, err);
            }
            else
            {
               reply(buf, len);
            }
         } : std::function<void(const void*,size_t,Message&,error*)>(),
         &cancel,
         err
      );
      ERROR_CHECK(err);
   }
   else
   {
      SendTcp(
         server,
         state->request.data(),
         state->request.size(),
         nullptr,
         [reply, advance] (const void *buf, size_t len, Message &msg, error *err) -> void
         {
            if (!len || msg.Header->Truncated)
               advance();
            else
               reply(buf, len);
         exit:;
         },
         &cancel,
         err
      );
      ERROR_CHECK(err);
   }

   try
   {
      if (cancel)           
         state->cancel.push_back(cancel);
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   pollster::get_common_queue(loop.GetAddressOf(), err);
   ERROR_CHECK(err);

   loop->add_timer(
      state->udpExhausted ? 1000 : 250,
      false,
      [&] (pollster::event *ev, error *err) -> void
      {
         ev->on_signal = [advance] (error *err) -> void
         {
            advance();
         };
      },
      timer.GetAddressOf(),
      err
   );
   ERROR_CHECK(err);

exit:;
}

void
dns::Server::TryForwardPacket(
   const struct sockaddr *addr,
   void *buf, size_t len,
   const Message &msg,
   const std::function<void(const void *, size_t, error *)> &innerReply,
   error *err      
)
{
   if (addr && udpDeDupe.Lookup(addr, msg))
      return;

   if (!forwardServers.size())
   {
      error_set_unknown(err, "no forward servers");
      return;
   }

   if (!msg.Questions.size())
   {
      error_set_unknown(err, "expected question");
      return;
   }

   if (!msg.Header->RecursionDesired)
   {
      error_set_unknown(err, "recursion not desired");
      return;
   }

   uint16_t originalId;
   std::shared_ptr<std::vector<std::function<void()>>> cancelVec;
   int cancelIdx = 0;
   std::function<void()> cancel;
   bool replyWritten = false;
   std::shared_ptr<ForwardClientState> *reqp = nullptr, req;

   try
   {
      cancelVec = std::make_shared<std::vector<std::function<void()>>>();
      cancelVec->resize((addr ? 1 : 0) + 1);
      cancel = [cancelVec] () -> void
      {
         for (auto &fn : *cancelVec)
         {
            if (fn)
               fn();
            else
               break;
         }
      };
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }

   if (addr)
   {
      udpDeDupe.Insert(addr, msg, true, cancelVec->data()+cancelIdx, err);
      ERROR_CHECK(err);
      ++cancelIdx;
   }

   memcpy(&originalId, &msg.Header->Id, sizeof(msg.Header->Id));
   memset(&msg.Header->Id, 0, sizeof(msg.Header->Id));

   // See if we already have a request for this.
   //
   reqp = forwardReqs.Lookup(nullptr, msg);
   if (reqp)
   {
      // Yep.
      //
      req = *reqp;
   }
   else
   {
      // Nope.
      //
      try
      {
         req = std::make_shared<ForwardClientState>();
         req->request.insert(req->request.begin(), (char*)buf, (char*)buf+len);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
      forwardReqs.Insert(nullptr, msg, req, cancelVec->data()+cancelIdx, err);
      ERROR_CHECK(err);
      ++cancelIdx;
   }

   //
   // Hook up our reply callback and cancellation
   //
   try
   {
      auto reply = [originalId, innerReply] (const void *buf, size_t len, error *err) -> void
      {
         uint16_t id;
         auto hdr = (MessageHeader*)buf;
         memcpy(&id, &hdr->Id, sizeof(hdr->Id));
         memcpy(&hdr->Id, &originalId, sizeof(hdr->Id));
         innerReply(buf, len, err);
         memcpy(&hdr->Id, &id, sizeof(hdr->Id));
      };

      req->reply.push_back(std::move(reply));
      replyWritten = true;

      if (cancelIdx)
      {
         if (cancelIdx == 1)
            req->cancel.push_back(std::move(*cancelVec->data()));
         else
         {
            cancelVec->resize(cancelIdx);
            cancelVec->shrink_to_fit();
            req->cancel.push_back(std::move(cancel));
         }
      }
      cancel = std::function<void()>();
   }
   catch (std::bad_alloc)
   {
      if (replyWritten)
         req->reply.erase(req->reply.end()-1);
      ERROR_SET(err, nomem);
   }

   //
   // If this is an old request, we're done, we've already sent packets.
   //
   if (reqp)
      goto exit;

   if (!rng)
   {
      rng_init(&rng, err);
      ERROR_CHECK(err);
   }

   TryForwardPacket(req, err);
   ERROR_CHECK(err);

exit:
   if (cancel)
      cancel();
}

void
dns::Server::AddForwardServer(
   const struct sockaddr *sa,
   Protocol proto,
   error *err
)
{
   try
   {
      auto state = std::make_shared<ForwardServerState>();

      state->proto = proto;

      auto &vec = state->sockaddr;
      auto sap = (const char*)sa;
      vec.insert(vec.end(), sap, sap+pollster::socklen(sa));

      forwardServers.push_back(std::move(state));
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

void
dns::Server::ClearForwardServers()
{
   forwardServers.resize(0);
}
