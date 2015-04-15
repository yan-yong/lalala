include $(top_srcdir)/common.mk

AM_CPPFLAGS=-I$(boost_path)/include -I$(common_path)
AM_LDFLAGS=-rdynamic -lpthread -L$(common_path)/_lib -llog -lhttpparser -lz -lcrypto -lrt -lfetcher -lutility -lssl -lhttpserver -lbitmap

LDADD=$(boost_path)/lib/libboost_system.a $(boost_path)/lib/libboost_thread.a $(common_path)/_lib/libjson.a $(boost_path)/lib/libboost_regex.a

sbin_PROGRAMS=proxy_scanner
proxy_scanner_SOURCES=main.cpp ProxyScanner.cpp
