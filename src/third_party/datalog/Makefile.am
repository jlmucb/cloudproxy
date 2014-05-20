bin_PROGRAMS = datalog
lib_LTLIBRARIES = libdatalog.la
include_HEADERS = datalog.h
info_TEXINFOS = datalog.texi
pkgdata_DATA = datalog.lua datalog.html
dist_man_MANS = datalog.1
noinst_PROGRAMS = bin2c
dist_noinst_SCRIPTS = datalogimport datalogexport

if NO_LUA
  SUBDIRS = lua
  AM_CPPFLAGS = -I$(srcdir)/lua
  LOCAL_LIBLUA = lua/liblua.a
endif

libdatalog_la_SOURCES = datalog.h loader.c datalog.c
libdatalog_la_LDFLAGS = -version-info 0:0:0

datalog_SOURCES = interp.c
datalog_LDADD = libdatalog.la $(LOCAL_LIBLUA)
datalog_DEPENDENCIES = libdatalog.la $(LOCAL_LIBLUA)

BUILT_SOURCES = dl_lua.h

bin2c_SOURCES = bin2c.c

dl_lua.h:	bin2c$(EXEEXT) datalog.lua
	./bin2c -o $@ datalog.lua

AM_MAKEINFOHTMLFLAGS = --no-split

EXTRA_DIST = datalog.html try.sh ancestor.dl ancestor.txt bidipath.dl	\
bidipath.txt laps.dl laps.txt long.dl long.txt path.dl path.txt pq.dl	\
pq.txt revpath.dl revpath.txt tc.dl tc.txt true.dl true.txt says.dl	\
says.txt octal.dl octal.txt add.lua pq.lua even.lua stackless.diff
