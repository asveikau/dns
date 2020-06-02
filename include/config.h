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
std::function<void(char*, error*)>
ConfigSectionHandler;

typedef
std::map<std::string, ConfigSectionHandler>
ConfigFileMap;

void
ParseConfigFile(
   common::Stream *stream,
   const ConfigFileMap &sectionHandlers,
   error *err
);

ConfigSectionHandler
MakeArgvParser(const std::function<void(int, char **, error *)> &func);

ConfigSectionHandler
MakeSingleArgParser(const std::function<void(char *, char *, error *)> &func);

#endif
