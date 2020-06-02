/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/pollster.h>

#include <common/logger.h>
#include <common/path.h>

#include <common/c++/stream.h>

#include <dnsserver.h>
#include <config.h>

#include <stdio.h>

static
char *get_config_file(error *err);

int
main(int argc, char **argv)
{
   error err;
   common::Pointer<pollster::waiter> loop;
   std::shared_ptr<dns::Server> srv;
   char *conffile = nullptr;

   libcommon_set_argv0(argv[0]);

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   pollster::create(loop.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   pollster::set_common_queue(loop.Get());

   pollster::socket_startup(&err);
   ERROR_CHECK(&err);

   try
   {
      srv = std::make_shared<dns::Server>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   conffile = get_config_file(&err);
   error_clear(&err);

   if (conffile)
   {
      common::Pointer<common::Stream> stream;
      ConfigFileMap map;

      // TODO: initialize map

      CreateStream(conffile, "r", stream.GetAddressOf(), &err);
      ERROR_CHECK(&err);

      ParseConfigFile(stream.Get(), map, &err);
      ERROR_CHECK(&err);

      free(conffile);
   }

   {
      struct sockaddr_in in;
      pollster::sockaddr_set_af(&in);
      in.sin_addr.s_addr = 0x08080808U;
      in.sin_port = htons(853);

      srv->AddForwardServer("dns.google", (struct sockaddr*)&in, dns::Protocol::DnsOverTls, &err);
      ERROR_CHECK(&err);
   }

   srv->StartUdp(AF_INET, &err);
   ERROR_CHECK(&err);
   srv->StartUdp(AF_INET6, &err);
   if (ERROR_FAILED(&err))
      error_clear(&err);

   srv->StartTcp(&err);
   ERROR_CHECK(&err);

   for (;;)
   {
      loop->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}

static
char *get_config_file(error *err)
{
   static const char conffile[] = "dns.conf";
   char *r = nullptr, *s = nullptr, *t = nullptr, *u = nullptr;
   const char *progname = get_program_path(err);
   ERROR_CHECK(err);

   s = strdup(progname);
   if (!s)
      ERROR_SET(err, nomem);
   for (t=s; (u = strpbrk(t, PATH_SEP_PBRK)); t=u+1)
      ;
   if (t == s)
      ERROR_SET(err, unknown, "Can't find path separator");
   *t = 0;

   r = append_path(s, conffile, err);
   ERROR_CHECK(err);
   if (!path_exists(r, err))
   {
      ERROR_CHECK(err);

      free(r);
      u = append_path(s, "../etc", err);
      ERROR_CHECK(err);
      r = append_path(s, conffile, err);
      free(u);
      ERROR_CHECK(err);

      if (!path_exists(r, err))
      {
         ERROR_CHECK(err);
         free(r);
         r = nullptr;
      }
   }

exit:
   free(s);
   if (ERROR_FAILED(err))
   {
      free(r);
      r = nullptr;
   }
   return r;
}
