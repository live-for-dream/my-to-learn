#
# Makefile
# Copyright (C) 2005-2006 NTT Corporation
#

.PHONY:		all install uninstall clean spotless dep depend

OBJS=tcpcp.o

CFLAGS=-g -fPIC -Wall -I../include

include ./Config

all:		.depend libtcpcp.so.$(LIBVERSION)

libtcpcp.so.$(LIBVERSION):	libtcpcp.so
				/sbin/ldconfig -n .

libtcpcp.so:	libtcpcp.a
		$(LD) -shared -soname libtcpcp.so \
		  -o libtcpcp.so.$(LIBVERSION) --whole-archive libtcpcp.a || \
		  { rm -f libtcpcp.so; exit 1; }

libtcpcp.a:	$(OBJS)
		$(AR) crv libtcpcp.a $(OBJS) || { rm -f libtcpcp.a; exit 1; }

# ----- Installation ----------------------------------------------------------

install:	all
		install -d $(HINSTPREFIX)/include
		install ../include/tcpcp.h $(HINSTPREFIX)/include
		install -d $(INSTPREFIX)/lib64
		install libtcpcp.so.$(LIBVERSION) $(INSTPREFIX)/lib64
		ln -s ./libtcpcp.so.$(LIBVERSION) \
		  $(INSTPREFIX)/lib64/libtcpcp.so

# ----- Cleanup ---------------------------------------------------------------

clean:
		rm -f $(OBJS) libtcpcp.a libtcpcp.so libtcpcp.so.$(LIBVERSION) \
		  .depend

# ---- Dependencies ----------------------------------------------------------

dep depend .depend:
		$(CPP) $(CFLAGS) -MM -MG *.c >.depend || \
		  { rm -f .depend; exit 1; }

ifeq (.depend,$(wildcard .depend))
include .depend
endif
