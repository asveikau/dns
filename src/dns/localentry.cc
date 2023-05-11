/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>

#include <dnsserver.h>
#include <dnsmsg.h>

#include <common/logger.h>

dns::LocalEntry
dns::Server::ParseLocalEntry(int argc, char **argv, error *err)
{
   LocalEntry entry;
   int i = 0;

   while (i < argc)
   {
      auto arg = argv[i++];
      if (!strcmp(arg, "ip"))
      {
         if (i >= argc)
         {
            log_printf("ip: expected arg\n");
            break;
         }
         auto ip = argv[i++];
         union
         {
            struct sockaddr sa;
            struct sockaddr_in in;
            struct sockaddr_in6 in6;
         } addr;
         pollster::sockaddr_set_af(&addr.sa, strchr(ip, ':') ? AF_INET6 : AF_INET);
         if (!pollster::string_to_sockaddr(&addr.sa, ip))
         {
            log_printf("%s: IP address failed to parse\n", ip);
            continue;
         }

         Type type;

         switch (addr.sa.sa_family)
         {
         case AF_INET:
            type = Type::A;
            break;
         case AF_INET6:
            type = Type::AAAA;
            break;
         default:
            continue;
         }

         const void *buf = nullptr;
         int off = 0;
         size_t len = 0;

         if (!internal::ParseAddr(&addr.sa, off, len))
            continue;

         buf = ((char*)&addr) + off;

         try
         {
            std::vector<char> vec;

            vec.insert(vec.begin(), (char*)buf, (char*)buf+len);

            entry.Addrs.push_back(std::make_pair(type, std::move(vec)));
         }
         catch (const std::bad_alloc &)
         {
            ERROR_SET(err, nomem);
         }
      }
      else if (!strcmp(arg, "ether"))
      {
         if (i >= argc)
         {
            log_printf("ether: expected arg\n");
            break;
         }
         auto ether = argv[i++];
      }
      else
      {
         log_printf("unexpected token: %s\n", arg);
      }
   }

exit:
   return entry;
}

bool
dns::Server::TryLocalEntry(
   const std::string sanitizedHostname,
   const Message &msg,
   const std::function<void(const void *, size_t, error *)> &reply
)
{
   error err;
   auto recp = localEntries.find(sanitizedHostname);
   if (recp != localEntries.end())
   {
      auto &rec = recp->second;
      MessageWriter response;
      Type type;
      bool any;

      response.Header->Id = msg.Header->Id;

      auto q = response.AddQuestion(&err);
      ERROR_CHECK(&err);
      try
      {
         q->Name = msg.Questions[0].Name;
      }
      catch (const std::bad_alloc &)
      {
         ERROR_SET(&err, nomem);
      }
      *q->Attrs = *msg.Questions[0].Attrs;

      switch ((Class)q->Attrs->Class.Get())
      {
      case Class::IN:
      case Class::Any:
         break;
      default:
         goto skip;
      }

      type = (Type)q->Attrs->Type.Get();
      any = ((QType)type == QType::ALL);

      for (auto &match : rec.Addrs)
      {
         if (any || type == match.first)
         {
            auto &blob = match.second;
            auto answer = response.AddAnswer((uint16_t)blob.size(), &err);
            const auto ttl = 5 * 60;
            ERROR_CHECK(&err);

            try
            {
               answer->Name = msg.Questions[0].Name;
            }
            catch (const std::bad_alloc &)
            {
               ERROR_SET(&err, nomem);
            }
            answer->Attrs->Type.Put((uint16_t)match.first);
            answer->Attrs->Class.Put((uint16_t)Class::IN);
            answer->Attrs->Ttl.Put(ttl);
            memcpy(answer->Attrs->Data, blob.data(), blob.size());
         }
      }

   skip:

      response.Header->Id.Put(msg.Header->Id.Get());
      response.Header->Response = 1;
      response.Header->RecursionAvailable = 1;

      if (!rec.Addrs.size())
         response.Header->ResponseCode = (unsigned)ResponseCode::NameError;

      auto blob = response.Serialize(&err);
      ERROR_CHECK(&err);

      reply(blob.data(), blob.size(), &err);
      ERROR_CHECK(&err);

      return true;
   }
exit:
   return false;
}
