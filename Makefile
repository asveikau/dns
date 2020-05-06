.PHONY: all all-phony clean depend
all: all-phony

CFLAGS += -O2 -Wall
WINDOWS_SUBSYSTEM=console

MAKEFILES_ROOT?=submodules/makefiles/
LIBCOMMON_ROOT?=submodules/common/
LIBPOLLSTER_ROOT?=submodules/pollster/
-include ${LIBPOLLSTER_ROOT}Makefile.inc
CFLAGS += -Iinclude -I$(LIBCOMMON_ROOT)include -I$(LIBPOLLSTER_ROOT)include
CXXFLAGS += $(CFLAGS)
LDFLAGS += -L$(LIBPOLLSTER_ROOT) -lpollster
LDFLAGS += -L$(LIBCOMMON_ROOT) -lcommon

SRCFILES += \
   src/main.cc \
   src/dns/parse.cc \
   src/dns/reqmap.cc \
   src/dns/server.cc \
   src/dns/tcp.cc \
   src/dns/udp.cc

APPNAME=dns

OBJS += $(shell $(SRC2OBJ) $(SRCFILES))

all-phony: $(APPNAME)$(EXESUFFIX)

$(APPNAME)$(EXESUFFIX): $(LIBCOMMON) $(LIBPOLLSTER) $(OBJS) $(XP_SUPPORT_OBJS)
	$(CXX) -o $@ $(OBJS) $(TIMESTAMP_OBJ) $(LDFLAGS)
	$(STRIP) $@

-include depend.mk

clean:
	rm -f $(LIBCOMMON) $(LIBCOMMON_OBJS)
	rm -f $(LIBPOLLSTER) $(LIBPOLLSTER_OBJS)
	rm -f $(APPNAME)$(EXESUFFIX) $(OBJS) $(XP_SUPPORT_OBJS)
	rm -f *.debug

export
depend:
	env $(DEPEND) \
           src/*.cc src/dns/*.cc \
        > depend.mk
