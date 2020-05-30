/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef dns_reqmap_h_
#define dns_reqmap_h_

#include <assert.h>

#include <map>
#include <string>
#include <vector>

#include "dnsmsg.h"

struct sockaddr;

namespace dns {

namespace internal
{
   bool
   ParseAddr(const struct sockaddr *addr, int &off, size_t &len);
}

template<typename Value>
class RequestMap
{
private:
   struct RequestData
   {
      std::vector<char> sockaddr;
      uint16_t type;
      std::string name;
      Value value;
   };

   std::map<uint16_t, std::vector<RequestData>> map;

public:

   Value *
   Lookup(const struct sockaddr *addr, const Message &msg)
   {
      auto id = msg.Header->Id.Get();
      if (msg.Questions.size() != 1)
         return nullptr;
      auto type = msg.Questions[0].Attrs->Type.Get();
      auto p = map.find(id);
      if (p == map.end())
         return nullptr;
      auto &resList = p->second;
      int off = 0;
      size_t len = 0;
      internal::ParseAddr(addr, off, len);
      for (auto &res : resList)
      {
         if (type != res.type)
            continue;
         if (len != res.sockaddr.size())
            continue;
         if (len && memcmp((const char*)addr+off, res.sockaddr.data(), len))
            continue;
         if (msg.Questions[0].Name != res.name)
            continue;
         return &res.value;
      }
      return nullptr;
   }

   void
   Insert(const struct sockaddr *addr, const Message &msg, const Value &value, error *err)
   {
      auto id = msg.Header->Id.Get();
      RequestData state;

      if (msg.Questions.size() != 1)
         ERROR_SET(err, unknown, "Expected question");

      try
      {
         int off = 0;
         size_t len = 0;
         if (internal::ParseAddr(addr, off, len))
         {
            auto p = (const char *)addr + off;
            state.sockaddr.insert(state.sockaddr.begin(), p, p+len);
         }
         state.type = msg.Questions[0].Attrs->Type.Get();
         state.name = msg.Questions[0].Name;
         state.value = value;
         map[id].push_back(std::move(state));
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }
   exit:;
   }

   void
   Insert(const struct sockaddr *addr, const Message &msg, const Value &value, std::function<void()> *cancel, error *err)
   {
      // TODO: cancel
      Insert(addr, msg, value, err);
   }

   void
   Remove(uint16_t id, Value *value)
   {
      auto it = map.find(id);
      if (it == map.end())
         return;

      Remove(it->second, value);
   }

   void
   Remove(Value *value)
   {
      for (auto &pair : map)
      {
         auto &list = pair->second;
         if (InVec(list, value))
         {
            Remove(list, value);
            break;
         }
      }
   }

private:
   template<typename T>
   static bool
   InVec(const std::vector<T> &list, void *p)
   {
      return list.size() && list.data() <= p && p < list.data()+list.size();
   }

   static void
   Remove(std::vector<RequestData> &list, Value *value)
   {
      assert(InVec(list, value));
      auto res = (RequestData*)((char*)value - offsetof(RequestData, value));
      list.erase(list.begin() + (res - list.data()));
   }
};

class ResponseMap
{
public:
   typedef std::function<void(
      const void *buf,
      size_t len,
      Message &msg,
      error *err
   )> Callback;

   void
   OnResponse(
      const struct sockaddr *,
      const void *buf,
      size_t len,
      Message &msg,
      error *err
   );

   void
   OnRequest(
      const struct sockaddr *addr,
      const Message &msg,
      const Callback &cb,
      std::function<void()> *cancel,
      error *err
   );

   void
   OnRequest(
      const struct sockaddr *addr,
      const void *buf,
      size_t len,
      const Message *msg,
      const Callback &cb,
      std::function<void()> *cancel,
      error *err
   );

private:
   RequestMap<Callback> reqs;
};

} // end namespace

#endif