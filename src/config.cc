/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include "config.h"

#include <ctype.h>
#include <string.h>
#include <vector>

#include <common/c++/linereader.h>

void
ParseConfigFile(
   common::Stream *stream,
   const ConfigFileMap &sectionHandlers,
   error *err
)
{
   ConfigFileState state;
   common::LineReader reader(stream);
   char *line = nullptr;
   const ConfigSectionHandler *fn = nullptr;

   while ((line = reader.ReadLine(err)))
   {
      size_t len = 0;
      while (isspace(*line))
         ++line;

      char *comment = strchr(line, '#');
      if (comment)
         *comment = 0;

      len = strlen(line);

      comment = line+len-1;
      while (comment >= line && isspace(*comment))
      {
         *comment-- = 0;
         --len;
      }

      if (!*line)
         continue;

      if (line[0] == '[' && line[len-1] == ']')
      {
         line[len-1] = 0;
         ++line;
         len -= 2;

         while (isspace(*line))
         {
            ++line;
            --len;
         }

         while (len && isspace(line[len-1]))
         {
            line[--len] = 0;
         }

         try
         {
            auto p = sectionHandlers.find(std::string(line, len));
            if (p != sectionHandlers.end())
               fn = &p->second;
            else
               fn = nullptr;
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }

         continue;
      }

      if (fn && *fn)
      {
         (*fn)(line, state, err);
         ERROR_CHECK(err);
      }
   }
   ERROR_CHECK(err);

   for (auto &fn : state.PendingActions)
   {
      fn(err);
      ERROR_CHECK(err);
   }

exit:;
}

void
AddConfigHandler(
   ConfigFileMap &map,
   const char *name,
   const ConfigSectionHandler &handler,
   error *err
)
{
   try
   {
      auto str = std::string(name);
      auto p = map.find(str);
      if (p == map.end())
      {
         map[str] = handler;
      }
      else
      {
         auto inner = std::move(p->second);
         map[str] = [handler, inner] (char *line, ConfigFileState& state, error *err) -> void
         {
            std::vector<char> copy;
            try
            {
               copy.insert(copy.end(), line, line+strlen(line)+1);
            }
            catch (std::bad_alloc)
            {
               ERROR_SET(err, nomem);
            }
            inner(copy.data(), state, err);
            ERROR_CHECK(err);
            handler(line, state, err);
            ERROR_CHECK(err);
         exit:;
         };
      }
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(err, nomem);
   }
exit:;
}

ConfigSectionHandler
MakeArgvParser(const std::function<void(int, char **, ConfigFileState&, error *)> &func)
{
   return [func] (char *cmdline, ConfigFileState& state, error *err) -> void
   {
      std::vector<char *> argv;
      try
      {
         char *p = cmdline;
         while (*p)
         {
            argv.push_back(p);
            while (*p && !isspace(*p))
               ++p;
            if (*p)
            {
               *p++ = 0;
               while (isspace(*p))
                  ++p;
            }
         }
         argv.push_back(nullptr);
      }
      catch (std::bad_alloc)
      {
         ERROR_SET(err, nomem);
      }

      func(argv.size()-1, argv.data(), state, err);
   exit:;
   };
}

ConfigSectionHandler
MakeSingleArgParser(const std::function<void(char *, char *, ConfigFileState& state, error *)> &func)
{
   return [func] (char *cmdline, ConfigFileState& state, error *err) -> void
   {
      char *p = cmdline;

      while (*p && !isspace(*p))
         ++p;

      if (*p)
      {
         *p++ = 0;
         while (isspace(*p))
            ++p;
      }
      else
      {
         p = nullptr;
      }

      func(cmdline, p, state, err);
   };
}
