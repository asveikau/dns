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

   // TODO: start sending packets

   if (!rng)
   {
      rng_init(&rng, err);
      ERROR_CHECK(err);
   }

#if 0
   rng_generate(rng, &msg.Header->Id, sizeof(msg.Header->Id), err);
   ERROR_CHECK(err);
#endif

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
