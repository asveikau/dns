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

namespace {

class StreamReader
{
   common::Pointer<common::Stream> stream;
   char buf[1024];
   size_t off;
   size_t inBuf;
   std::vector<unsigned char> lineBuf;
public:
   StreamReader(common::Stream *str) : stream(str), off(0), inBuf(0) {}
   StreamReader(const StreamReader &) = delete;

   int
   ReadChar(error *err)
   {
      int c = EOF;

      if (off == inBuf)
      {
         off = inBuf = 0;

         inBuf = stream->Read(buf, sizeof(buf), err);
         ERROR_CHECK(err);
         if (!inBuf)
            goto exit;
      }

      c = buf[off++];
   exit:
      return c;
   }

   char *
   ReadLine(error *err)
   {
      // TODO: if we can find a line terminator within the current buffer,
      // return it directly.

      lineBuf.resize(0);

      for (;;)
      {
         int c = ReadChar(err);
         ERROR_CHECK(err);

         switch (c)
         {
         case EOF:
            if (!lineBuf.size())
               goto exit;
            c = 0;
            break;
         case '\r':
            // Try to convert CRLF to LF.
            c = ReadChar(err);
            ERROR_CHECK(err);
            // Put back any non-'\n' char
            if (c != EOF && c != '\n')
               off--;
            // fall through
         case '\n':
            c = 0;
            break;
         }

         try
         {
            lineBuf.push_back(c);
         }
         catch (std::bad_alloc)
         {
            ERROR_SET(err, nomem);
         }
         if (c == 0)
            break;
      }

      return (char*)lineBuf.data();
   exit:
      return nullptr;
   }
};

} // end namespace

void
ParseConfigFile(
   common::Stream *stream,
   const ConfigFileMap &sectionHandlers,
   error *err
)
{
   StreamReader reader(stream);
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
         (*fn)(line, err);
         ERROR_CHECK(err);
      }
   }
   ERROR_CHECK(err);

exit:;
}

ConfigSectionHandler
MakeArgvParser(const std::function<void(int, char **, error *)> &func)
{
   return [func] (char *cmdline, error *err) -> void
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

      func(argv.size()-1, argv.data(), err);
   exit:;
   };
}

ConfigSectionHandler
MakeSingleArgParser(const std::function<void(char *, char *, error *)> &func)
{
   return [func] (char *cmdline, error *err) -> void
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

      func(cmdline, p, err);
   };
}
