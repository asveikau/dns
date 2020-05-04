/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef dnsserver_h_
#define dnsserver_h_ 1

#include <stddef.h>
#include <functional>

#include <common/error.h>

namespace dns {

class Server
{
protected:
   void
   HandleMessage(
      void *buf, size_t len,
      const std::function<void(const void *, size_t, error *)> &reply,
      error *err
  );
public:
   void
   StartUdp(int af, error *err);

   void
   StartTcp(error *err);
};

} // end namespace

#endif
