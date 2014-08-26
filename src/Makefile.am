lib_LTLIBRARIES = librtmp.la

librtmpincludedir = $(includedir)/librtmp
librtmpinclude_HEADERS = \
  amf.h \
  log.h \
  rtmp.h \
  rtmp_sys.h

librtmp_la_SOURCES = \
  amf.c \
  hashswf.c \
  log.c \
  parseurl.c \
  rtmp.c

librtmp_la_CFLAGS =

# this implementation is LGPL, and hence we can't build
# it statically:
librtmp_la_LDFLAGS = \
  -shared \
  -lcrypto \
  -lssl \
  -lz

