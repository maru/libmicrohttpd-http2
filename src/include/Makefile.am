# This Makefile.am is in the public domain
SUBDIRS = .

include_HEADERS = microhttpd.h
if ENABLE_HTTP2
include_HEADERS += \
  microhttpd_http2.h
endif

noinst_HEADERS = microhttpd2.h microhttpd_tls.h

EXTRA_DIST = platform.h autoinit_funcs.h mhd_options.h
