AC_INIT(Datalog, 2.4)

AC_CONFIG_SRCDIR(datalog.c)

AM_INIT_AUTOMAKE

AC_PROG_CC_C99

# Add warning when using GGG
if test "X$GCC" = Xyes ; then
  CFLAGS="$CFLAGS -Wall"
fi

LT_INIT([disable-shared])

AC_SEARCH_LIBS([exp], [m])

AC_CHECK_HEADERS([readline/readline.h readline/history.h])

AC_SEARCH_LIBS([readline], [readline])

AC_SEARCH_LIBS([add_history], [readline],
	       [AC_DEFINE(HAVE_LIBREADLINE, 1,
                 [Define if you have a readline compatible library])])

AC_ARG_WITH([lua],
  [AS_HELP_STRING([--with-lua],
    [use installed lua package [default=no]])],
  [],
  [with_lua=no])

# Look for correct version of installed Lua
# when --with-lua is not no or --with-lua-suffix is defined.
if test "x$with_lua" != xno -o -n "$with_lua_suffix" ; then
  AC_CHECK_HEADERS([lua.h lualib.h lauxlib.h],
                   [], AC_MSG_FAILURE([lua header not found]))
  AX_LUA_HEADERS_VERSION([501], [503])
  AC_SEARCH_LIBS([lua_pushboolean], [lua$with_lua_suffix],
                 [], AC_MSG_FAILURE([lua library not found]))
fi

AM_CONDITIONAL([NO_LUA], [test "x$with_lua" = xno -a -z "$with_lua_suffix"])

AC_CONFIG_FILES([Makefile lua/Makefile datalog.spec datalog.lua])

AC_OUTPUT
