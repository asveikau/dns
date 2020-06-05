/*
 Copyright (C) 2020 Andrew Sveikauskas

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
*/

#include <pollster/socket.h>
#include <pollster/pollster.h>

#include <common/logger.h>
#include <common/path.h>
#include <common/misc.h>

#include <common/c++/stream.h>

#include <dnsserver.h>
#include <config.h>

#include <stdio.h>

#if !defined(_WINDOWS)
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#endif

static
char *get_config_file(error *err);

int
main(int argc, char **argv)
{
   error err;
   common::Pointer<pollster::waiter> loop;
   std::shared_ptr<dns::Server> srv;
   char *conffile = nullptr;
   struct
   {
      std::string chroot, setuid, setgid;
   } secargs;

   libcommon_set_argv0(argv[0]);

   log_register_callback(
      [] (void *np, const char *p) -> void { fputs(p, stderr); },
      nullptr
   );

   pollster::create(loop.GetAddressOf(), &err);
   ERROR_CHECK(&err);

   pollster::set_common_queue(loop.Get());

   pollster::socket_startup(&err);
   ERROR_CHECK(&err);

   try
   {
      srv = std::make_shared<dns::Server>();
   }
   catch (std::bad_alloc)
   {
      ERROR_SET(&err, nomem);
   }

   conffile = get_config_file(&err);
   error_clear(&err);

   if (conffile)
   {
      common::Pointer<common::Stream> stream;
      ConfigFileMap map;

      AddConfigHandler(
         map,
         "security",
         MakeSingleArgParser(
            [&secargs] (char *cmd, char *arg, error *err) -> void
            {
               size_t cmdlen = strlen(cmd)+1;
#define WRAP_STRING(x) static const char str_##x [] = #x
               WRAP_STRING(chroot);
               WRAP_STRING(setuid);
               WRAP_STRING(setgid);
#undef WRAP_STRING
#define CMP(x) (cmdlen == sizeof(str_##x) && !strcmp(cmd, str_##x) && arg && *arg)
               try
               {
                  if (CMP(chroot))
                     secargs.chroot = arg;
                  else if (CMP(setuid))
                     secargs.setgid = arg;
                  else if (CMP(setgid))
                     secargs.setuid = arg;
                  else
                     log_printf("conf: security: unrecognized command %s", cmd);
               }
               catch (std::bad_alloc)
               {
                  error_set_nomem(err);
               }
#undef CMP
            }
         ),
         &err
      );
      ERROR_CHECK(&err);

      // TODO: initialize map further

      CreateStream(conffile, "r", stream.GetAddressOf(), &err);
      ERROR_CHECK(&err);

      ParseConfigFile(stream.Get(), map, &err);
      ERROR_CHECK(&err);

      free(conffile);
   }

   {
      struct sockaddr_in in;
      pollster::sockaddr_set_af(&in);
      in.sin_addr.s_addr = 0x08080808U;
      in.sin_port = htons(853);

      srv->AddForwardServer("dns.google", (struct sockaddr*)&in, dns::Protocol::DnsOverTls, &err);
      ERROR_CHECK(&err);
   }

   srv->StartUdp(AF_INET, &err);
   ERROR_CHECK(&err);
   srv->StartUdp(AF_INET6, &err);
   if (ERROR_FAILED(&err))
      error_clear(&err);

   srv->StartTcp(&err);
   ERROR_CHECK(&err);

#if !defined(_WINDOWS)
   {
      auto parseInteger = [] (const char *id, const std::function<bool(const char*, long long&)> &fn, const char *msg, error *err) -> int64_t
      {
         char *end = nullptr;
         auto value = strtoll(id, &end, 10);
         errno = 0;
         if ((id != end && !*end) || fn(id, value))
            return value;
         if (errno)
            error_set_errno(err, errno);
         else
            error_set_unknown(err, msg);
         return 0;
      };
      auto parseUser = [parseInteger] (const char *user, error *err) -> uid_t
      {
         return parseInteger(
            user,
            [] (const char *user, long long &r) -> bool
            {
               auto pw = getpwnam(user);
               if (pw)
               {
                  r = pw->pw_uid;
                  return true;
               }
               return false;
            },
            "Could not lookup user",
            err
         );
      };
      auto parseGroup = [parseInteger] (const char *group, error *err) -> gid_t
      {
         return parseInteger(
            group,
            [] (const char *group, long long &r) -> bool
            {
               auto gr = getgrnam(group);
               if (gr)
               {
                  r = gr->gr_gid;
                  return true;
               }
               return false;
            },
            "Could not lookup group",
            err
         );
      };
      uid_t user = 0;
      gid_t group = 0;

      if (secargs.setuid.size())
      {
         user = parseUser(secargs.setuid.c_str(), &err);
         if (ERROR_FAILED(&err))
         {
            log_printf("Cannot find user %s", secargs.setuid.c_str());
            goto exit;
         }
      }

      if (secargs.setgid.size())
      {
         group = parseGroup(secargs.setgid.c_str(), &err);
         if (ERROR_FAILED(&err))
         {
            log_printf("Cannot find group %s", secargs.setgid.c_str());
            goto exit;
         }
      }

      if (secargs.chroot.size() && (chroot(secargs.chroot.c_str()) || chdir("/")))
      {
         int e = errno;
         log_printf("Cannot chroot into %s", secargs.chroot.c_str());
         ERROR_SET(&err, errno, e);
      }

      if (secargs.setgid.size() && setgid(group))
      {
         int e = errno;
         log_printf("Failed to setgid to %s", secargs.setgid.c_str());
         ERROR_SET(&err, errno, e);
      }

      if (secargs.setuid.size() && setuid(user))
      {
         int e = errno;
         log_printf("Failed to setuid to %s", secargs.setuid.c_str());
         ERROR_SET(&err, errno, e);
      }
   }
#endif

   for (;;)
   {
      loop->exec(&err);
      ERROR_CHECK(&err);
   }

exit:
   return ERROR_FAILED(&err) ? 1 : 0;
}

static
char *get_config_file(error *err)
{
   static const char conffile[] = "dns.conf";
   char *r = nullptr, *s = nullptr, *t = nullptr, *u = nullptr;
   const char *progname = get_program_path(err);
   ERROR_CHECK(err);

   s = strdup(progname);
   if (!s)
      ERROR_SET(err, nomem);
   for (t=s; (u = strpbrk(t, PATH_SEP_PBRK)); t=u+1)
      ;
   if (t == s)
      ERROR_SET(err, unknown, "Can't find path separator");
   *t = 0;

   r = append_path(s, conffile, err);
   ERROR_CHECK(err);
   if (!path_exists(r, err))
   {
      ERROR_CHECK(err);

      free(r);
      u = append_path(s, "../etc", err);
      ERROR_CHECK(err);
      r = append_path(s, conffile, err);
      free(u);
      ERROR_CHECK(err);

      if (!path_exists(r, err))
      {
         ERROR_CHECK(err);
         free(r);
         r = nullptr;
      }
   }

exit:
   free(s);
   if (ERROR_FAILED(err))
   {
      free(r);
      r = nullptr;
   }
   return r;
}
