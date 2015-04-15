include $(top_srcdir)/common.mk

AM_CPPFLAGS=-I$(boost_path)/include -I$(common_path)
AM_LDFLAGS=-rdynamic -lpthread -lz -lcrypto -lrt -lssl

LDADD=$(boost_path)/lib/libboost_system.a \
	$(boost_path)/lib/libboost_thread.a \
	$(boost_path)/lib/libboost_regex.a \
	$(common_path)/_lib/liblog.a \
	$(common_path)/_lib/libjson.a \
	$(common_path)/_lib/libhttpparser.a \
	$(common_path)/_lib/libfetcher.a \ 
	$(common_path)/_lib/libutility.a \
	$(common_path)/_lib/libhttpserver.a \
	$(common_path)/_lib/libbitmap.a

sbin_PROGRAMS=proxy_scanner
proxy_scanner_SOURCES=main.cpp ProxyScanner.cpp
