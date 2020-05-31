/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsserver.h>
#include <dnsmsg.h>

//
// These are the entry points for future expansion.  For now there is no cache.
//

bool
dns::Server::TryCache(
   const Message &msg,
   const std::function<void(const void *, size_t, error *)> &reply
)
{
   return false;
}

void
dns::Server::CacheReply(const void *buf, size_t len)
{
   Message msg;
   error errStorage;
   error *err = &errStorage;

   ParseMessage(buf, len, &msg, err);
   ERROR_CHECK(err);

   // TODO
exit:;
}
