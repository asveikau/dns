/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <dnsserver.h>

void
dns::Server::AddForwardServer(
   const struct sockaddr *sa,
   error *err
)
{
   try
   {
      std::vector<char> vec;
      auto sap = (const char*)sa;
      vec.insert(vec.end(), sap, sap+pollster::socklen(sa));
      forwardServers.push_back(std::move(vec));
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