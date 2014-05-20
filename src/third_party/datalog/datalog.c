/*
 * Implements a C API for a small Datalog interpreter written in Lua.
 *
 * John D. Ramsdell
 * Copyright (C) 2004 The MITRE Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/* See the header file datalog.h for comments about the C API.
   Comments in this file focus on the implemention only. */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "datalog.h"
#include "dl_lua.h"

static int dl_pcall(dl_db_t L, int nargs, int nresults)
{
  int i = lua_pcall(L, nargs, nresults, 0);
  if (i) {
    const char *s = lua_tostring(L, -1);
    if (s)
      fprintf(stderr, "%s\n", s);
    else
      fprintf(stderr, "no error message available\n");
    lua_pop(L, 1);
  }
  return i;
}

static int
dl_lua(dl_db_t L)
{
  int i = luaL_loadbuffer(L, (const char *)datalog_lua_bytes,
			  sizeof(datalog_lua_bytes), datalog_lua_source);
  if (i) {
    const char *s = lua_tostring(L, -1);
    if (s)
      fprintf(stderr, "%s\n", s);
    else
      fprintf(stderr, "no error message available\n");
    lua_pop(L, 1);
    return i;
  }
  else
    return dl_pcall(L, 0, 0);
}

static const luaL_Reg lualibs[] = {
#if LUA_VERSION_NUM < 502
  {"", luaopen_base},
#else
  {"_G", luaopen_base},
#endif
  {LUA_TABLIBNAME, luaopen_table},
  {LUA_STRLIBNAME, luaopen_string},
  {NULL, NULL}
};

DATALOG_API dl_db_t
dl_open(void)
{
  lua_State *L = luaL_newstate();
  const luaL_Reg *lib = lualibs; /* Load libraries used by the */
  for (; lib->func; lib++) {	 /* Lua datalog program. */
#if LUA_VERSION_NUM < 502
    lua_pushcfunction(L, lib->func);
    lua_pushstring(L, lib->name);
    lua_call(L, 1, 0);
#else
    luaL_requiref(L, lib->name, lib->func, 1);
    lua_pop(L, 1);		/* remove lib */
#endif
  }
  if (dl_lua(L))		/* Load the Lua program. */
    return NULL;
  else
    return L;
}

DATALOG_API int
dl_init(dl_db_t L)
{
  return dl_lua(L);
}

DATALOG_API void
dl_close(dl_db_t L)
{
  lua_close(L);
}

/* Return package name and version information. */
DATALOG_API const char *
dl_version(void)
{
  return
#ifdef PACKAGE_NAME
    PACKAGE_NAME
#else
    "Datalog"
#endif
    " "
#ifdef VERSION
    VERSION
#else
    "version unknown"
#endif
    ;
}

/* Stack: ... -> ... string */
DATALOG_API int
dl_pushlstring(dl_db_t L, const char *s, size_t n)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_pushlstring(L, s, n);
  return 0;
}

/* Stack: ... -> ... string */
DATALOG_API int
dl_pushstring(dl_db_t L, const char *s)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_pushstring(L, s);
  return 0;
}

/* Stack: ... string string -> ... string */
DATALOG_API int
dl_concat(dl_db_t L)
{
  lua_concat(L, 2);
  return 0;
}

/* Stack: ... -> ... table */
DATALOG_API int
dl_pushliteral(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_pushliteral");
  return dl_pcall(L, 0, 1);
}

/* Stack: ... table string -> ... table */
DATALOG_API int
dl_addpred(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_addpred");
  lua_insert(L, -3);
  return dl_pcall(L, 2, 1);
}

/* Stack: ... table string -> ... table */
DATALOG_API int
dl_addvar(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_addvar");
  lua_insert(L, -3);
  return dl_pcall(L, 2, 1);
}

/* Stack: ... table string -> ... table */
DATALOG_API int
dl_addconst(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_addconst");
  lua_insert(L, -3);
  return dl_pcall(L, 2, 1);
}

/* Stack: ... table -> ... literal */
DATALOG_API int
dl_makeliteral(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_makeliteral");
  lua_insert(L, -2);
  return dl_pcall(L, 1, 1);
}

/* Stack: ... literal -> ... table */
DATALOG_API int
dl_pushhead(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_pushhead");
  lua_insert(L, -2);
  return dl_pcall(L, 1, 1);
}

/* Stack: ... table literal -> ... table */
DATALOG_API int
dl_addliteral(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_addliteral");
  lua_insert(L, -3);
  return dl_pcall(L, 2, 1);
}

/* Stack: ... table -> ... clause */
DATALOG_API int
dl_makeclause(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_makeclause");
  lua_insert(L, -2);
  return dl_pcall(L, 1, 1);
}

/* Stack: ... clause -> ... */
DATALOG_API int
dl_assert(dl_db_t L)
{
  int i;
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_assert");
  lua_insert(L, -2);
  i = dl_pcall(L, 1, 1);
  if (i)
    return i;
  i = lua_isnil(L, -1);		/* Return -1 when Lua function */
  lua_pop(L, 1);		/* returns nil to indicate */
  return -i;			/* an unsafe clause.  */
}

/* Stack: ... clause -> ... */
DATALOG_API int
dl_retract(dl_db_t L)
{
  if (!lua_checkstack(L, 1))
    return 1;
  lua_getglobal(L, "dl_retract");
  lua_insert(L, -2);
  return dl_pcall(L, 1, 0);
}

/* The dl_ask function returns the list of facts it derives from a
   literal provided as the function's query.  A pointer to the
   dl_answers structure represents the list. */

struct dl_answers {
  size_t arity;
  size_t len;
  char **pred;
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
  char **term[1];
#else
  char **term[];
#endif
};

/* There are three blocks of memory that make up a list of answers.
   The name of the predicate and all the constant terms are placed in
   one array of characters.  An array of character pointers is used to
   delimit the strings within the character array.  Finally, the
   memory allocated to a dl_answers structure contains a pointer to
   the predicated in pred[0] and for the ith answer, the first term
   is at term[i][0], and the jth term of the ith answer is at
   term[i][j].

   For example, the answer list: {p(a,b), p(xy,z)} is represented with
   by following three blocks of memory.

        struct answers		 char*[]           char[]
          ---------              -------           ------
          arity   2              [0]  0            [0] p
          len     2              [1]  2            [1] 0
          pred    0   	       	 [2]  4            [2] a
          term[0] 1              [3]  6            [3] 0
          term[1] 3		 [4]  9		   [4] b
                   		 [5] 11       	   [5] 0
       					           [6] x
       	       	       	       	       	           [7] y
					           [8] 0
					           [9] z
       	       	       	       	       	          [10] 0
*/

DATALOG_API void
dl_free(dl_answers_t a)
{
  if (a) {
    free(a->pred[0]);		/* Free char array. */
    free(a->pred);		/* Free char * array. */
    free(a);			/* Free struct dl_answers. */
  }
}

/* Stack: ... literal -> ... */
DATALOG_API int
dl_ask(dl_db_t L, dl_answers_t *a)
{
  int i, j;
  lua_Integer n;		/* Number of answers. */
  lua_Integer arity;		/* Arity of predicate. */
  lua_Integer size;	      /* Size of the character array block. */
  size_t len;		     /* Used to compute lengths of strings. */
  char *s;		   /* Stores the location to insert a char. */
  const char *ls;	   /* A string from lua. */
  char **p;		 /* Stores the location to insert a char *. */
  dl_answers_t b;
  *a = NULL;
  if (!lua_checkstack(L, 1))
    return 1;

  lua_getglobal(L, "dl_ask");
  lua_insert(L, -2);
  i = dl_pcall(L, 1, 1);
  if (i)
    return i;
  if (!lua_istable(L, -1)) {
    i = !lua_isnil(L, -1);	/* Nil indicates no answers. */
    lua_pop(L, 1);
    return i;
  }

  lua_pushstring(L, "n");	/* Get number of answers. */
  lua_rawget(L, -2);
  if (!lua_isnumber(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  n = lua_tointeger(L, -1);
  lua_pop(L, 1);
  if (n == 0)			/* If no answers, return NULL. */
    return 0;

  lua_pushstring(L, "arity");	/* Get arity. */
  lua_rawget(L, -2);
  if (!lua_isnumber(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  arity = lua_tointeger(L, -1);
  lua_pop(L, 1);

  lua_pushstring(L, "size");	/* Get the size of char */
  lua_rawget(L, -2);		/* array computed by Lua. */
  if (!lua_isnumber(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  size = lua_tointeger(L, -1);
  lua_pop(L, 1);

  if (n < 0 || arity < 0 || size < 0)
    return 1;

  s = (char *)malloc(size);	/* Allocate the three blocks. */
  p = (char **)malloc((n * arity + 2) * sizeof(char *));
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
  b = (dl_answers_t)malloc(sizeof(struct dl_answers)
			   + (n - 1) * sizeof(char **));
#else
  b = (dl_answers_t)malloc(sizeof(struct dl_answers) + n * sizeof(char **));
#endif
  if (!s || !p || !b)
    return 1;		       /* Abort on memory allocation error. */

  b->arity = arity;
  b->len = n;
  p[0] = s;
  b->pred = p;

  lua_pushstring(L, "name");	/* Get predicate name. */
  lua_rawget(L, -2);
  if (!lua_isstring(L, -1)) {
    lua_pop(L, 2);
    dl_free(b);
    return 1;
  }
  ls = lua_tolstring(L, -1, &len); /* Get string and length. */
  len++;			   /* Make room for null byte. */
  memcpy(s, ls, len);		   /* Copy string. */
  s += len;		/* Update s to be the next unused location. */
  *++p = s;    /* Update p to be the next location and set it to s. */
  lua_pop(L, 1);

  for (i = 0; i < n; i++) {	/* For each answer. */
    b->term[i] = p;		/* Record the answer start. */
    lua_rawgeti(L, -1, i + 1);
    if (!lua_istable(L, -1)) {	/* Get one answer. */
      lua_pop(L, 2);
      dl_free(b);
      return 1;
    }
    for (j = 1; j <= arity; j++) {
      lua_rawgeti(L, -1, j);	/* For each term in an answer. */
      if (!lua_isstring(L, -1)) {
	lua_pop(L, 3);
	dl_free(b);
	return 1;
      }
      ls = lua_tolstring(L, -1, &len); /* Get string and length. */
      len++;			       /* Make room for null byte. */
      memcpy(s, ls, len);	       /* Copy string. */
      s += len;
      *++p = s;
      lua_pop(L, 1);
    }
    lua_pop(L, 1);
  }
  lua_pop(L, 1);		/* Remove the array */

  *a = b;			/* Return result and */
  return 0;			/* indicate success. */
}

DATALOG_API char *
dl_getpred(dl_answers_t a)
{
  if (a)
    return a->pred[0];
  else
    return NULL;
}

DATALOG_API size_t
dl_getpredlen(dl_answers_t a)
{
  if (a)
    return a->pred[1] - a->pred[0] - 1;
  else
    return 0;
}

DATALOG_API size_t
dl_getpredarity(dl_answers_t a)
{
  if (a)
    return a->arity;
  else
    return 0;
}

DATALOG_API char *
dl_getconst(dl_answers_t a, int i, int j)
{
  if (!a || i < 0 || i >= a->len || j < 0 || j >= a->arity)
    return NULL;
  else
    return a->term[i][j];
}

DATALOG_API size_t
dl_getconstlen(dl_answers_t a, int i, int j)
{
  if (!a || i < 0 || i >= a->len || j < 0 || j >= a->arity)
    return 0;
  else
    return a->term[i][j + 1] - a->term[i][j] - 1;
}

/* Stack ... thing -> ... */
DATALOG_API int
dl_pop(dl_db_t L)
{
  lua_pop(L, 1);
  return 0;
}

/* Marks the stack. */
DATALOG_API int
dl_mark(dl_db_t L)
{
  return lua_gettop(L);
}

/* Resets the stack height to the mark. */
DATALOG_API int
dl_reset(dl_db_t L, int m)
{
  lua_settop(L, m);
  return 0;
}
