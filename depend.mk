# This file was generated by "make depend".
#

src/main.o: src/main.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/logger.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h include/dnsreqmap.h include/dnsserver.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/forward.o: src/dns/forward.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h include/dnsmsg.h include/dnsproto.h include/dnsreqmap.h include/dnsserver.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/parse.o: src/dns/parse.cc $(LIBCOMMON_ROOT)include/common/error.h include/dnsmsg.h include/dnsproto.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/reqmap.o: src/dns/reqmap.cc $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h include/dnsmsg.h include/dnsproto.h include/dnsreqmap.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/server.o: src/dns/server.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h include/dnsmsg.h include/dnsproto.h include/dnsreqmap.h include/dnsserver.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/tcp.o: src/dns/tcp.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h include/dnsmsg.h include/dnsproto.h include/dnsreqmap.h include/dnsserver.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/udp.o: src/dns/udp.cc $(LIBCOMMON_ROOT)include/common/c++/handle.h $(LIBCOMMON_ROOT)include/common/c++/refcount.h $(LIBCOMMON_ROOT)include/common/crypto/rng.h $(LIBCOMMON_ROOT)include/common/error.h $(LIBCOMMON_ROOT)include/common/misc.h $(LIBCOMMON_ROOT)include/common/mutex.h $(LIBCOMMON_ROOT)include/common/refcnt.h $(LIBCOMMON_ROOT)include/common/size.h $(LIBPOLLSTER_ROOT)include/pollster/filter.h $(LIBPOLLSTER_ROOT)include/pollster/pollster.h $(LIBPOLLSTER_ROOT)include/pollster/sockapi.h $(LIBPOLLSTER_ROOT)include/pollster/socket.h $(LIBPOLLSTER_ROOT)include/pollster/ssl.h include/dnsmsg.h include/dnsproto.h include/dnsreqmap.h include/dnsserver.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
src/dns/write.o: src/dns/write.cc $(LIBCOMMON_ROOT)include/common/error.h include/dnsmsg.h include/dnsproto.h
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $<
