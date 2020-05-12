/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <dnsproto.h>

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

