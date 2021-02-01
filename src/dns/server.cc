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

#include <string.h>

void
dns::Server::Initialize(error *err)
{
   if (!rng)
   {
      rng_init(&rng, err);
      ERROR_CHECK(err);
   }
exit:;
}

void
dns::Server::HandleMessage(
   MessageMode mode,
   void *buf, size_t len,
   const struct sockaddr *addr,
   ResponseMap &map,
   const std::function<void(const void *, size_t, error *)> &reply,
   error *err
)
{
   Message msg;
   ResponseCode rc = ResponseCode::ServerFailure;

   ParseMessage(buf, len, &msg, err);
   if (ERROR_FAILED(err))
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

   if (msg.Header->Response)
   {
      if ((int)mode & (int)MessageMode::Client)
         map.OnResponse(addr, buf, len, msg, err);
      return;
   }
   else if (!((int)mode & (int)MessageMode::Server))
      return;

   // Several DNS servers reject more than one question per packet.
   //
   if (msg.Header->QuestionCount.Get() != 1)
   {
      rc = ResponseCode::FormatError;
      goto errorReply;
   }

   if (TryCache(msg, reply))
      goto exit;

   TryForwardPacket(addr, buf, len, msg, reply, err);
   ERROR_CHECK(err);

exit:;
   if (ERROR_FAILED(err))
      goto errorReply;
   return;
errorReply:
   error_clear(err);
   if (((int)mode & (int)MessageMode::Server) &&
       len > 2 &&
       (len < 3 || !((MessageHeader*)buf)->Response))
   {
      MessageWriter writer;

      writer.Header->Id.Put(((MessageHeader*)buf)->Id.Get());
      writer.Header->Response = 1;
      writer.Header->ResponseCode = (unsigned)rc;
      writer.Header->RecursionAvailable = 1;

      for (auto q : msg.Questions)
      {
         auto qq = writer.AddQuestion(err);
         if (ERROR_FAILED(err))
            break;
         qq->Name = std::move(q.Name);
         *qq->Attrs = *q.Attrs;
      }

      auto vec = writer.Serialize(err);

      if (ERROR_FAILED(err))
      {
         error_clear(err);
         writer.Header->QuestionCount.Put(0);
         reply(writer.Header, sizeof(*writer.Header), err);
      }
      else
      {
         reply(vec.data(), vec.size(), err);
      }
      error_clear(err);
   }
}

void
dns::Server::AttachConfig(ConfigFileMap &map, error *err)
{
   AddConfigHandler(
      map,
      "dns",
      MakeArgvParser(
         [this] (int argc, char **argv, ConfigFileState& state, error *err) -> void
         {
            if (!argc)
               return;
            const char *cmd = argv[0];
            size_t cmdlen = strlen(cmd)+1;
#define WRAP_STRING(x) static const char str_##x [] = #x
            WRAP_STRING(search);
            WRAP_STRING(nameserver);
#undef WRAP_STRING
#define CMP(x) (cmdlen == sizeof(str_##x) && !strcmp(cmd, str_##x))
            try
            {
               if (CMP(search))
               {
                  if (argc > 1)
                     searchPath = argv[1];
               }
               else if (CMP(nameserver))
               {
                  const char *proto = nullptr;
                  const char *host = nullptr;
                  int port = 53;

                  union
                  {
                     struct sockaddr sa;
                     struct sockaddr_in in;
                     struct sockaddr_in6 in6;
                  } addr;

                  auto try_parse = [&addr, &port] (const char *str) -> bool
                  {
                     pollster::sockaddr_set_af(&addr.sa, AF_INET);

                     if (pollster::string_to_sockaddr(&addr.sa, str))
                     {
                        addr.in.sin_port = htons(port);
                        return true;
                     }

                     pollster::sockaddr_set_af(&addr.sa, AF_INET6);

                     if (pollster::string_to_sockaddr(&addr.sa, str))
                     {
                        addr.in6.sin6_port = htons(port);
                        return true;
                     }

                     return false;
                  };

                  dns::Protocol protoEnum;

                  if (argc < 2)
                     return;

                  proto = argv[1];
                  host = argv[2];

                  if (!strcmp(proto, "dns"))
                     protoEnum = dns::Protocol::Plaintext;
                  else if (!strcmp(proto, "tls"))
                  {
                     protoEnum = dns::Protocol::DnsOverTls;
                     port = 853;
                  }
                  else
                  {
                     log_printf("unrecognized protocol: %s", proto);
                     return;
                  }

                  if (try_parse(host))
                  {
                     // Host is actually an IP.
                     //
                     host = nullptr;
                     AddForwardServer(host, &addr.sa, protoEnum, err);
                     ERROR_CHECK(err);
                  }

                  for (int i=3; i<argc; ++i)
                  {
                     const char *ip = argv[i];
                     if (!try_parse(ip))
                     {
                        log_printf("Could not parse address: %s", ip);
                        continue;
                     }
                     AddForwardServer(host, &addr.sa, protoEnum, err);
                     ERROR_CHECK(err);
                  }
               }
               else
                  log_printf("conf: dns: unrecognized command %s", cmd);
            }
            catch (const std::bad_alloc&)
            {
               error_set_nomem(err);
            }
#undef CMP
         exit:;
         }
      ),
      err
   );
   ERROR_CHECK(err);
   AddConfigHandler(
      map,
      "hosts",
      MakeArgvParser(
         [this] (int argc, char **argv, ConfigFileState& state, error *err) -> void
         {
            try
            {
               std::string hostname = argv[0];
               auto entry = ParseLocalEntry(argc-1, argv+1, err);
               ERROR_CHECK(err);
               state.PendingActions.push_back(
                  [this, hostname, entry] (error *err) mutable -> void
                  {
                     auto trimDots = [&] () -> void
                     {
                        while (hostname.length() && hostname[hostname.length()-1] == '.')
                        {
                           hostname.resize(hostname.length()-1);
                        }
                     };
                     if (!strchr(hostname.c_str(), '.') && searchPath.length())
                     {
                        trimDots();
                        if (!hostname.length())
                           goto exit;
                        try
                        {
                           hostname += '.';
                           hostname += searchPath;
                        }
                        catch (const std::bad_alloc &)
                        {
                           ERROR_SET(err, nomem);
                        }
                     }
                     trimDots();
                     if (!hostname.length())
                        goto exit;
                     hostname = SanitizeHost(hostname, err);
                     ERROR_CHECK(err);
                     try
                     {
                        localEntries[hostname] = std::move(entry);
                     }
                     catch (const std::bad_alloc &)
                     {
                        ERROR_SET(err, nomem);
                     }
                  exit:;
                  }
               );
            }
            catch (const std::bad_alloc &)
            {
            }
         exit:;
         }
      ),
      err
   );
   ERROR_CHECK(err);
exit:;
}
