/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsproto.h>
#include <dnsmsg.h>

#include <algorithm>
#include <map>

void
dns::I16::Put(uint16_t value)
{
   auto p = (unsigned char*)&this->value;
   p[0] = (value >> 8);
   p[1] = (value & 0xff);
}

void
dns::I32::Put(uint32_t value)
{
   auto p = (unsigned char*)&this->value;
   p[0] = (value >> 24);
   p[1] = (value >> 16);
   p[2] = (value >> 8);
   p[3] = (value & 0xff);
}

namespace
{

struct StringTable
{
   struct Node
   {
      int rc;
      std::string payload;
      Node *next;
      std::vector<uint16_t> offsets;
      uint16_t myOffset;

      Node() : rc(1), next(nullptr), myOffset(0) {}
   };
   struct TreeNode
   {
      Node *data;
      std::map<std::string, TreeNode> Items;

      TreeNode() : data(nullptr) {}
   };
   TreeNode root;
   std::vector<Node*> allNodes;
   std::map<std::string, Node *> allNodesByName;

   ~StringTable()
   {
      for (auto n : allNodes)
         delete n;
   }

   void
   Insert(const std::string &str)
   {
      auto n = Lookup(str);
      if (n)
      {
         n->rc++;
         return;
      }

      TreeNode *tn = &root;
      auto begin = str.c_str();
      auto p = begin+str.size();
      do
      {
         auto q = p;
         while (p > begin && *p == '.')
            --p;
         while (p > begin && *p != '.')
            --p;
         auto r = (p == begin) ? p : p+1;

         std::string tmp(r, q-r);

         auto next = tn->Items.find(tmp);
         if (next == tn->Items.end())
         {
            tn->Items[tmp] = TreeNode();
            next = tn->Items.find(tmp);
         }
         auto nn = &next->second;
         if (!nn->data)
         {
            nn->data = new Node();
            if (p != begin)
               nn->data->rc = 0;
            try
            {
               allNodes.push_back(nn->data);
            }
            catch (const std::bad_alloc&)
            {
               delete nn->data;
               nn->data = nullptr;
               throw;
            }
            nn->data->next = tn->data;
            nn->data->payload = std::move(tmp);

            if (tn->data)
               tn->data->rc++;

            allNodesByName[std::string(r)] = nn->data;
         }
         tn = nn;
      } while (p > begin);
   }

   Node *
   Lookup(const std::string &str)
   {
      auto p = allNodesByName.find(str);
      if (p == allNodesByName.end())
         return nullptr;
      return p->second;
   }

   void
   Compact()
   {
      root.Items = std::map<std::string, TreeNode>();

      for (auto p : allNodes)
      {
         while (p->next && p->next->rc == 1)
         {
            p->payload += '.';
            p->payload += p->next->payload;
            p->next->payload = std::string();
            p->next->rc = 0;
            p->next = p->next->next;
         }
      }

      for (auto p : allNodes)
      {
         if (p->rc == 1 && !p->next)
            p->rc = 0;
      }

      for (auto i = allNodesByName.begin(); i != allNodesByName.end(); )
      {
         if (!i->second->rc)
            i = allNodesByName.erase(i);
         else
            ++i;
      }

      allNodes.erase(
         std::remove_if(
            allNodes.begin(), allNodes.end(),
            [] (Node *n) -> bool
            {
               if (!n->rc)
               {
                  delete n;
                  return true;
               }
               return false;
            }
         ),
         allNodes.end()
      );
   }
};

} // end namespace

std::vector<char>
dns::MessageWriter::Serialize(error *err)
{
   std::vector<char> r;

   try
   {
      auto hdr = (const char*)Header;
      r.insert(r.end(), hdr, hdr+sizeof(*Header));

      StringTable table;

      for (auto &r : Questions)
         table.Insert(r.Name);

      for (auto rlist : {&answerReqs, &authorityReqs, &additlRecs})
      {
         for (auto &r : *rlist)
            table.Insert(r.Name);
      }

      table.Compact();

      auto writePayload = [&] (const char *p, size_t len) -> void
      {
         if (!len)
            r.push_back(0);
         while (len)
         {
            size_t l = len;
            int shift = 0;

            auto q = p;
            while (q < p+len && *q != '.')
               ++q;
            if (q < p+len && *q == '.')
            {
               l = q-p;
               shift = 1;
            }

            if (l >= 64)
            {
               error_set_unknown(err, "Invalid length");
               return;
            }
            r.push_back((char)l);
            r.insert(r.end(), p, p+l);

            l += shift;
            p += l;
            len -= l;
         }
      };

      auto writeName = [&] (const std::string &str) -> void
      {
         const char *p = nullptr;
         size_t len = 0;
         auto n = table.Lookup(str);
         if (n)
         {
            if (n->rc == 1)
            {
               p = n->payload.data();
               len = n->payload.size();
               n = n->next;
            copyString:
               writePayload(p, len);
               if (ERROR_FAILED(err))
                  return;
               if (!n)
               {
                  if (len)
                     writePayload(nullptr, 0);
                  return;
               }
            }
            n->offsets.push_back(r.size());
            r.push_back(0);
            r.push_back(0);
            return;
         }
         p = str.data();
         len = str.size();
         goto copyString;
      };

      for (auto &q : Questions)
      {
         auto p = (const char*)q.Attrs;
         writeName(q.Name);
         ERROR_CHECK(err);
         r.insert(r.end(), p, p+sizeof(*q.Attrs));
      }

      for (auto rlist : {&answerReqs, &authorityReqs, &additlRecs})
      {
         for (auto &rr : *rlist)
         {
            auto p = (const char*)rr.Attrs;
            writeName(rr.Name);
            ERROR_CHECK(err);
            r.insert(r.end(), p, p+offsetof(RecordAttrs, Data)+rr.Attrs->Length.Get());
         }
      }

      bool shouldRetry = false;
   retry:
      for (auto n : table.allNodes)
      {
         if (n->offsets.size())
         {
            if (r.size() >= 0x4000)
               ERROR_SET(err, unknown, "Pointer too big");
            n->myOffset = r.size();

            writePayload(n->payload.data(), n->payload.size());
            if (!n->next)
            {
               if (n->payload.size())
                  writePayload(nullptr, 0);
            }
            else if (n->next->myOffset)
            {
               unsigned char sz[] =
               {
                  (unsigned char)(0xc0U | (n->next->myOffset >> 8)),
                  (unsigned char)(n->next->myOffset & 0xff),
               };
               r.push_back(sz[0]);
               r.push_back(sz[1]);
            }
            else
            {
               n->next->offsets.push_back(r.size());
               r.push_back(0);
               r.push_back(0);
               shouldRetry = true;
            }
            for (auto off : n->offsets)
            {
               unsigned char sz[] =
               {
                  (unsigned char)(0xc0U | (n->myOffset >> 8)),
                  (unsigned char)(n->myOffset & 0xff),
               };
               memcpy(r.data()+off, sz, sizeof(sz));
            }
            n->offsets.resize(0);
         }
      }
      if (shouldRetry)
      {
         shouldRetry = false;
         goto retry;
      }
   }
   catch (const std::bad_alloc&)
   {
      ERROR_SET(err, nomem);
   }

exit:
   return r;
}

dns::Record *
dns::MessageWriter::AddRecord(Record *&ptr, std::vector<Record> &vec, I16 &count, uint16_t payload, error *err)
{
   Record *r = nullptr;
   auto oldAttrs = rattrs.data();

   if (vec.size() == 0xffff)
      ERROR_SET(err, unknown, "Too many records");

   try
   {
      vec.resize(vec.size() + 1);
      r = &vec[vec.size()-1];
      auto oldSize = rattrs.size();
      rattrs.resize(oldSize + offsetof(RecordAttrs, Data) + payload);
      r->Attrs = (RecordAttrs*)((char*)rattrs.data() + oldSize);
      r->Attrs->Length.Put(payload);
      r->Attrs = (RecordAttrs*)((char*)oldAttrs + oldSize);
   }
   catch (const std::bad_alloc&)
   {
      if (r)
      {
         vec.resize(vec.size() - 1);
         r = nullptr;
      }
      ERROR_SET(err, nomem);
   }

   // If the attrs vector moved, we need to patch the old pointers.
   //
   if (oldAttrs != rattrs.data())
   {
      for (auto rlist : {&answerReqs, &authorityReqs, &additlRecs})
      {
         for (auto &r : *rlist)
         {
            r.Attrs = (RecordAttrs*)(rattrs.data() + ((char*)r.Attrs - oldAttrs));
         }
      }
   }

   count.Put(vec.size());
   ptr = vec.data();
   r = &vec[vec.size()-1];
exit:
   return r;
}

dns::Question *
dns::MessageWriter::AddQuestion(error *err)
{
   Question *r = nullptr;
   auto oldAttrs = qattrs.data();
   auto &vec = Questions;
   auto &count = Header->QuestionCount;

   if (vec.size() == 0xffff)
      ERROR_SET(err, unknown, "Too many records");

   try
   {
      vec.resize(vec.size() + 1);
      r = &vec[vec.size()-1];
      qattrs.resize(qattrs.size() + 1);
      r->Attrs = oldAttrs + qattrs.size() - 1;
   }
   catch (const std::bad_alloc&)
   {
      if (r)
      {
         vec.resize(vec.size() - 1);
         r = nullptr;
      }
      ERROR_SET(err, nomem);
   }

   if (oldAttrs != qattrs.data())
   {
      for (auto &r : Questions)
      {
         r.Attrs = qattrs.data() + (r.Attrs - oldAttrs);
      }
   }

   count.Put(vec.size());
   r = &vec[vec.size()-1];
exit:
   return r;
}