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
#include <vector>

struct ConfigFileState
{
   std::vector<std::function<void(error*)>> PendingActions;
};

typedef
std::function<void(char*, ConfigFileState&, error*)>
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
MakeArgvParser(const std::function<void(int, char **, ConfigFileState&, error *)> &func);

ConfigSectionHandler
MakeSingleArgParser(const std::function<void(char *, char *, ConfigFileState&, error *)> &func);

void
AddConfigHandler(
   ConfigFileMap &map,
   const char *name,
   const ConfigSectionHandler &handler,
   error *err
);

#endif
