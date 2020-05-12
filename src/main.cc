/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/pollster.h>

#include <common/logger.h>

#include <dnsserver.h>

#include <stdio.h>

int
main()
{
   error err;
   common::Pointer<pollster::waiter> loop;
   dns::Server srv;

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   pollster::create(loop.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   pollster::set_common_queue(loop.Get());

   pollster::socket_startup(&err);
   ERROR_CHECK(&err);

   {
      struct sockaddr_in in;
      pollster::sockaddr_set_af(&in);
      in.sin_addr.s_addr = 0x08080808U;
      in.sin_port = htons(53);

      srv.AddForwardServer((struct sockaddr*)&in, &err);
      ERROR_CHECK(&err);
   }

   srv.StartUdp(AF_INET, &err);
   ERROR_CHECK(&err);
   srv.StartUdp(AF_INET6, &err);
   if (ERROR_FAILED(&err))
      error_clear(&err);

   srv.StartTcp(&err);
   ERROR_CHECK(&err);

   for (;;)
   {
      loop->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}
