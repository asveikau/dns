# dns

This is an experimental forwarding DNS server written in C++ that was a bit of a
quarantine project for me.

Some interesting features:

* Support for DNS-over-TLS as both client and server.

   - For DNS-over-TLS server mode, point `dns.conf`'s `certificate` directive at a PEM
     file containing a cert chain and private key.

* Multi-platform.  Have tested on Linux, *BSD, Windows ...

## TODO

I had some further ideas of where to take this, notably I wanted to add DHCP support,
with hostnames for DHCP leases getting injected directly to the DNS server.

## Building

Building happens via [the makefiles submodule][1].

    $ git submodule update --init
    $ make                             # or "gmake" on some platforms, like BSD

On Windows, you may also need to:

    $ cd submodules/sqlitewrapper ; git submodule update --init

On Unix, the project builds with g++ 8.0 or higher (7 and earlier won't work!)
or clang++.

On Windows, GNU make, nasm and msysgit should be on PATH, and the project is
typically tested with VS2015 with Windows SDK 10586.

[1]: https://github.com/asveikau/makefiles
