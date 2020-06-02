/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#ifndef config_h_
#define config_h_

#include <common/c++/stream.h>
#include <functional>
#include <map>
#include <string>

typedef
std::map<std::string, std::function<void(const char*, error*)>>
ConfigFileMap;

void
ParseConfigFile(
   common::Stream *stream,
   const ConfigFileMap &sectionHandlers,
   error *err
);

#endif
