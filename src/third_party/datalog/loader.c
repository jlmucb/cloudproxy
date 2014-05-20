/*
 * A loader for Datalog programs and printers that use the loader's
 * syntax for constants.
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

/* The loader reads Datalog assertions and a query written in a
   Prolog-like syntax, and loads them into a Datalog theory.  When
   loading is successful, clauses in the source are asserted and
   become part of the theory.  A source file may specify a final
   literal, which is left on the theory's stack.  That literal is
   intended to be a query to be used with the prove action.  If a
   literal is not specified, a literal known to be false in every
   theory is left on the theory's stack. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <setjmp.h>
#include <lua.h>
#include "datalog.h"

/* The name of the equality predicate. */
#define EQUALS_PRED "="

/* Loader state. */
typedef struct {

  /* The Datalog theory in which assertions and queries are created. */
  dl_db_t db;

  /* Buffer handling for the scanner. */
  const char *position;		/* Points to the current character. */
  const char *limit;		/* Points to the end of the buffer. */
  void *data;		    /* Data supplied by and for the caller. */
  dl_reader_t reader;	      /* A caller supplied reader function. */
  dl_loaderror_t loaderror;    /* A caller supplied error reporter. */

  /* Scanner state other than the buffer. */
  int havepushedchar;		/* A boolean. */
  int pushedchar;		/* Character stored by ungetch. */
  int lastcol;		   /* Column that may be stored by ungetch. */
  int colno;			/* Current column number. */
  int lineno;			/* Current line number. */

  jmp_buf env;		       /* Used for non-local exit on error. */
} loader_t;

static void
err(loader_t *l, const char *msg) /* Report error and exit. */
{
  l->loaderror(l->data, l->lineno, l->colno, msg);
  longjmp(l->env, 1);
}

#define chk(l, i) chk_file_line((l), (i), __FILE__, __LINE__)

static void
chk_file_line(loader_t *l, int i, const char *file, int line)
{
#if defined DEBUG_LOADER
  if (i)
    fprintf(stderr, "%s:%d: Datalog API return value is %d\n", file, line, i);
#else
  (void)file;
  (void)line;
#endif
  if (i)
    err(l, "internal error");
}

typedef enum {			/* Tokens returned by the scanner. */
  ID, VAR, LPAREN, RPAREN, EQUAL, COMMA,
  IMPLY, PERIOD, TILDE, QUESTION, DONE, BAD
} token_t;

static void
getbuf(loader_t *l)		/* Use the caller supplied reader */
{				/* to get the next buffer. */
  size_t size;
  l->position = l->reader(l->data, &size);
  l->limit = l->position ? l->position + size : NULL;
}

static void
initscan(loader_t *l)
{
  l->havepushedchar = 0;
  l->lastcol = 0;
  l->colno = 0;
  l->lineno = 1;
  getbuf(l);
}

static int
getch(loader_t *l)
{
  int ch;
  if (l->havepushedchar) {	/* Use ungetch char if have one. */
    l->havepushedchar = 0;
    ch = l->pushedchar;
  }
  else {			/* Get char from buffer. */
    if (!l->position)
      return EOF;
    while (l->position >= l->limit) { /* Current buffer used up. */
      getbuf(l);
      if (!l->position)
	return EOF;
    } /* Get char from buffer.  Ensure ch is positive so that */
    ch = (unsigned char)*l->position++;	/* EOF is distinct. */
  }
  if (ch == '\n') {		/* Update char location info. */
    l->lineno++;
    l->lastcol = l->colno;
    l->colno = 0;
  }
  else
    l->colno++;
  return ch;
}

static void
ungetch(loader_t *l, int ch)
{
  l->pushedchar = ch;		/* Only one push back */
  l->havepushedchar = 1;	/* character allowed. */
  if (ch == '\n') {		/* Update char location info. */
    l->lineno--;
    l->colno = l->lastcol;
  }
  else
    l->colno--;
}

static int
isvarstart(int ch)		/* May character start a variable? */
{
  return isupper(ch);
}

static int
isvarpart(int ch)	  /* May character be a part of a variable? */
{
  return isalnum(ch) || ch == '_';
}

static int
isidpart(int ch)       /* May character be a part of an identifier? */
{
  switch (ch) {
  case '(':
  case ')':
  case '=':
  case ',':
  case '.':
  case '~':
  case '?':
  case ':':
  case '"':
  case '%':
    return 0;
  default:
    return isgraph(ch);
  }
}

static int
isidstart(int ch)	      /* May character start an identifier? */
{
  return isidpart(ch) && !isvarstart(ch);
}

static token_t
addid(loader_t *l)		/* Add an identifier. */
{
  int more = 0;			/* Is a string on the stack? */

  for (;;) {
    const char *mark = l->position - 1;
    int ch;

    while (l->position < l->limit) {
      ch = getch(l);
      if (!isidpart(ch)) {	/* If all of identifier */
	ungetch(l, ch);		/* is in current buffer, */
	chk(l, dl_pushlstring(l->db, mark, l->position - mark - 1));
	if (more)		/* just push it. */
	  chk(l, dl_concat(l->db));
	return ID;
      }
    }
				/* Push unfinished id on stack. */
    chk(l, dl_pushlstring(l->db, mark, l->position - mark));
    if (more)
      chk(l, dl_concat(l->db));
    else
      more = 1;

    ch = getch(l);		/* Force buffer reload. */
    ungetch(l, ch);		/* If first char in new buffer */
    if (!isidpart(ch))		/* completes identifier, */
      return ID;		/* we're done. */
  }
}

static token_t
addvar(loader_t *l)		/* Add a variable. */
{				/* See addid for comments. */
  int more = 0;

  for (;;) {
    const char *mark = l->position - 1;
    int ch;

    while (l->position < l->limit) {
      ch = getch(l);
      if (!isvarpart(ch)) {
	ungetch(l, ch);
	chk(l, dl_pushlstring(l->db, mark, l->position - mark - 1));
	if (more)
	  chk(l, dl_concat(l->db));
	return VAR;
      }
    }

    chk(l, dl_pushlstring(l->db, mark, l->position - mark));
    if (more)
      chk(l, dl_concat(l->db));
    else
      more = 1;

    ch = getch(l);
    ungetch(l, ch);
    if (!isidpart(ch))
      return VAR;
  }
}

/* Quoted string syntax:

1. The only characters that must be quoted are: ", \, or nl.

2. The sequence \ nl is ignored.

3. The character escapes are: a, b, f, n, r, t, v, \, ', ", ?.

4. The numeric escapes: one, two, or three octal digits.

*/

static int
isodigit(int ch)
{
  return '0' <= ch && ch <= '7';
}

static int
toint(int ch)
{
  return ch - '0';		/* Assumes isodigit(ch) */
}

static int
toescape(int ch)		/* Character escapes */
{
  switch (ch) {
  case 'a':
    return '\a';
  case 'b':
    return '\b';
  case 'f':
    return '\f';
  case 'n':
    return '\n';
  case 'r':
    return '\r';
  case 't':
    return '\t';
  case 'v':
    return '\v';
  case '\\':
    return '\\';
  case '\'':
    return '\'';
  case '"':
    return '"';
  case '?':
    return '?';
  default:
    return ch;
  }
}

/* State of string reading is either SEEN_NOTHING, SEEN_SLASH, or a
   non-negative number.  The SEEN_OCTAL MARK is added when two digits
   have been seen. */
#define SEEN_NOTHING -1
#define SEEN_SLASH -2
#define SEEN_OCTAL (1 << 12)

/* In C99, use a variable length array instead of malloc. */

/* Push a string that needs quote removal.  Last is true when this
   call completes the contents of a string. */
static int
pushstring(loader_t *l, int s0, int last, const char *s, size_t n)
{
  const char *end = s + n;	/* The address just beyond s */
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
  char *buf = (char *)malloc(n + 1);
#else
  char buf[n + 1];
#endif
  char *b = buf;   /* Points to the place to add the next character */
  int i;
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
  if (!buf)
    err(l, "memory exhausted");
#endif
  for (; s < end; s++) {
    int ch = *s;		/* For each item in source string. */
    if (s0 == SEEN_NOTHING) {	/* Dispatch based on state. */
      if (ch == '\\')
	s0 = SEEN_SLASH;
      else if (ch == '\n')
	err(l, "newline in string");
      else
	*b++ = ch;
    }
    else if (s0 == SEEN_SLASH) {
      if (isodigit(ch))
	s0 = toint(ch);
      else if (ch == 'x')
	err(l, "hexadecimal escape sequence in string");
      else {
	if (ch != '\n')		/* If ch is \n, do nothing. */
	  *b++ = toescape(ch);
	s0 = SEEN_NOTHING;
      }
    }
    else if (s0 < SEEN_OCTAL) { /* One octal digit seen. */
      if (isodigit(ch))
	s0 = SEEN_OCTAL + 8 * s0 + toint(ch);
      else {
	*b++ = s0;
	s--;	       /* Back up and look at this character later. */
	s0 = SEEN_NOTHING;
      }
    }
    else {			/* Two octal digits seen. */
      s0 -= SEEN_OCTAL;		/* Get rid of octal mark. */
      if (isodigit(ch))
	*b++ = 8 * s0 + toint(ch);
      else {
	*b++ = s0;
	s--;	       /* Back up and look at this character later. */
      }
      s0 = SEEN_NOTHING;
    }
  }

  if (last) {			/* Flush last byte at string end */
    if (s0 >= SEEN_OCTAL)
      *b++ = s0 - SEEN_OCTAL;
    else if (s0 >= 0)
      *b++ = s0;
  }

  i = dl_pushlstring(l->db, buf, b - buf);
#if !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
  free(buf);
#endif
  return i;
}

/* This is a very complicated function and has been the source of
   several obsure bugs.  It orchestrates the handling of reading a
   string that spans multiple buffers.  For a buffer that ends a
   string, it determines if the buffer needs escape sequences
   expanded, and hands off the task to the appropriate routine.  A
   buffer that has no escape sequences is not copied, and therefore
   handled very efficiently.  For a buffer that does not end the
   string, it computes the initial state for string processing by the
   next buffer, and then hands off the task of processing the current
   buffer to the appropriate routine.  To accomplish its task, this
   routine must compute states exactly as pushstring does. */

#define EMPTY_PUSHBACK (1 << 12)

static token_t
addstr(loader_t *l)		/* Add a quoted string. */
{				/* Understand addid before you */
  int more = 0;			/* study this function. */
  const char *mark = l->position;
  int s1 = SEEN_NOTHING;	/* Current state for a buffer. */

  for (;;) {			/* For each buffer */
    int ch;
    int s0 = s1;	/* s0 is the initial state for this buffer. */
    int quote = s0 != SEEN_NOTHING;
    int pushback = EMPTY_PUSHBACK;

    while (l->position < l->limit) {
      if (pushback == EMPTY_PUSHBACK)
	ch = getch(l);		/* For each character in the */
      else {			/* current buffer... */
	ch = pushback;
	pushback = EMPTY_PUSHBACK;
      }
      if (ch == EOF)
	err(l, "end of input in string");
      if (s1 == SEEN_NOTHING) {
	if (ch == '"') {
	  if (quote)		/* String is complete. */
	    chk(l, pushstring(l, s0, 1, mark, l->position - mark - 1));
	  else
	    chk(l, dl_pushlstring(l->db, mark, l->position - mark - 1));
	  if (more)
	    chk(l, dl_concat(l->db));
	  return ID;
	}
	else if (ch == '\\') {
	  s1 = SEEN_SLASH;
	  quote = 1;
	}
	else if (ch == '\n')
	  err(l, "newline in string");
      }
      else if (s1 == SEEN_SLASH) {
	if (isodigit(ch))
	  s1 = toint(ch);
	else		/* Non-numeric escapes take two characters. */
	  s1 = SEEN_NOTHING;
      }
      else if (s1 < SEEN_OCTAL) { /* One octal digit seen. */
	if (isodigit(ch))
	  s1 = SEEN_OCTAL + 8 * s1 + toint(ch);
	else {
	  pushback = ch;
	  s1 = SEEN_NOTHING;
	}
      }
      else {			/* Two octal digits seen. */
	if (!isodigit(ch))
	  pushback = ch;
	s1 = SEEN_NOTHING;
      }
    }

    if (pushback == '"') {
      if (quote)		/* String is complete. */
	chk(l, pushstring(l, s0, 1, mark, l->position - mark - 1));
      else
	chk(l, dl_pushlstring(l->db, mark, l->position - mark - 1));
      if (more)
	chk(l, dl_concat(l->db));
      return ID;
    }
    else if (pushback == '\\')
      s1 = SEEN_SLASH;
    else if (pushback == '\n')
      err(l, "newline in string");

    /* s1 is the initial state for the next buffer. */

    if (quote)
      chk(l, pushstring(l, s0, 0, mark, l->position - mark));
    else
      chk(l, dl_pushlstring(l->db, mark, l->position - mark));
    if (more)
      chk(l, dl_concat(l->db));
    else
      more = 1;

    ch = getch(l);		/* Force a buffer read. */
    if (ch == EOF)
      err(l, "end of input in string");
    if (s1 == SEEN_NOTHING && ch == '"')
      return ID;
    else
      ungetch(l, ch);
    mark = l->position - 1;
  }
}

static token_t
scan(loader_t *l)	       /* Entry point for lexical analysis. */
{
  int ch;
  for (;;) {
    do {			/* Ignore leading spaces. */
      ch = getch(l);
      if (ch == EOF)
	return DONE;
    } while (isspace(ch));
    if (ch != '%')
      break;
    do {			/* Ignore comments. */
      ch = getch(l);
      if (ch == EOF)
	return DONE;
    } while (ch != '\n');
  }

  switch (ch) {			/* Dispatch based on the character. */
  case '(':
    return LPAREN;
  case ')':
    return RPAREN;
  case '=':
    return EQUAL;
  case ',':
    return COMMA;
  case '.':
    return PERIOD;
  case '~':
    return TILDE;
  case '?':
    return QUESTION;
  case ':':
    ch = getch(l);
    if (ch == '-')
      return IMPLY;
    else
      return BAD;
  case '"':
    return addstr(l);
  default:
    if (isidstart(ch))
      return addid(l);
    else if(isvarstart(ch))
      return addvar(l);
    else
      return BAD;
  }
}

static void
term(loader_t *l)		/* Parse a term. Assumes a */
{				/* string is on the stack. */
  token_t token = scan(l);
  switch (token) {
  case ID:
    chk(l, dl_addconst(l->db));
    return;
  case VAR:
    chk(l, dl_addvar(l->db));
    return;
  default:
    err(l, "syntax error while expecting a term");
  }
}

static token_t			/* Parse a literal.  Assumes an */
literal(loader_t *l, token_t token) /* incomplete literal is on the */
{				/* stack.  Returns the token */
  if (token == ID) {		/* that follows the literal. */
    token = scan(l);
    switch (token) {
    case EQUAL:			/* Handle the binary infix */
      chk(l, dl_addconst(l->db)); /* equals predicate. */
      chk(l, dl_pushstring(l->db, EQUALS_PRED));
      chk(l, dl_addpred(l->db));
      term(l);
      chk(l, dl_makeliteral(l->db));
      return scan(l);
    case PERIOD:
    case COMMA:
    case IMPLY:
    case TILDE:
    case QUESTION:
      chk(l, dl_addpred(l->db)); /* Handle a predicate with */
      chk(l, dl_makeliteral(l->db)); /* an arity of zero. */
      return token;
    case LPAREN:
      chk(l, dl_addpred(l->db)); /* Handle a predicate with */
      term(l);			/* a non-zero arity. */
      for (;;) {
	token = scan(l);
	if (token == RPAREN) {
	  chk(l, dl_makeliteral(l->db));
	  return scan(l);
	}
	else if (token == COMMA)
	  term(l);
	else
	  err(l, "syntax error in a term list");
      }
    default:
      return token;		/* Let caller report this error. */
    }
  }
  else if (token == VAR) {	/* Handle the binary infix */
    chk(l, dl_addvar(l->db));	/* equals predicate. */
    token = scan(l);
    if (token != EQUAL) {
      if (token == LPAREN)
	err(l, "syntax error of a variable used as a predicate");
      else
	err(l, "syntax error while expecting an equals sign");
    }
    chk(l, dl_pushstring(l->db, EQUALS_PRED));
    chk(l, dl_addpred(l->db));
    term(l);
    chk(l, dl_makeliteral(l->db));
    return scan(l);
  }
  else {
    err(l, "syntax error while expecting a predicate");
    return BAD;
  }
}

static void			/* Parse the body of a rule. */
rule(loader_t *l)		/* Assumes a literal is on the */
{				/* stack. */
  int i;
  token_t token;
  chk(l, dl_pushhead(l->db));
  chk(l, dl_pushliteral(l->db));
  token = literal(l, scan(l));
  while (token == COMMA) {
    chk(l, dl_addliteral(l->db));
    chk(l, dl_pushliteral(l->db));
    token = literal(l, scan(l));
  }
  chk(l, dl_addliteral(l->db));
  chk(l, dl_makeclause(l->db));
  switch (token) {
  case PERIOD:			/* Assert a rule. */
    i = dl_assert(l->db);
    if (i == -1)
      err(l, "unsafe rule asserted");
    chk(l, i);
    return;
  case TILDE:			/* Retract a rule. */
    chk(l, dl_retract(l->db));
    return;
  default:
    err(l, "syntax error after a rule");
  }
}

static void
falsehood(loader_t *l)		/* Creates a literal known */
{				/* to be false. In this case, */
  chk(l, dl_pushstring(l->db, "0")); /* 0 = 1. */
  chk(l, dl_addconst(l->db));
  chk(l, dl_pushstring(l->db, EQUALS_PRED));
  chk(l, dl_addpred(l->db));
  chk(l, dl_pushstring(l->db, "1"));
  chk(l, dl_addconst(l->db));
  chk(l, dl_makeliteral(l->db));
}

static void
program(loader_t *l)		/* Parses a complete program. */
{
  int i;
  token_t token;
  for (;;) {
    chk(l, dl_pushliteral(l->db));
    token = scan(l);
    if (token == DONE) {
      falsehood(l);		/* Push a false literal */
      return;			/* as the query. */
    }
    token = literal(l, token);
    switch (token) {
    case PERIOD:		/* Assert a fact. */
      chk(l, dl_pushhead(l->db));
      chk(l, dl_makeclause(l->db));
      i = dl_assert(l->db);	/* Assert a clause. */
      if (i == -1)
	err(l, "unsafe fact asserted");
      chk(l, i);
      break;
    case TILDE:			/* Retract a fact. */
      chk(l, dl_pushhead(l->db));
      chk(l, dl_makeclause(l->db));
      chk(l, dl_retract(l->db));
      break;
    case QUESTION:		/* Query found. */
      token = scan(l);
      if (token != DONE)
	err(l, "syntax error while expecting end of input");
      return;
    case IMPLY:
      rule(l);
      break;
    default:
      err(l, "syntax error after a fact");
    }
  }
}

/* Main loader entry point. */
DATALOG_API int
dl_load(dl_db_t db, dl_reader_t r, dl_loaderror_t le, void *d)
{
  loader_t l;			/* State of loader allocated on stack. */
  int mark = dl_mark(db);
  int status = setjmp(l.env);	/* Set up non-local error exit. */
  if (status) {
    dl_reset(db, mark);
    return status;
  }
  if (!db)
    err(&l, "missing theory");
  l.db = db;
  if (!r)
    err(&l, "missing reader");
  l.reader = r;
  if (!le)
    err(&l, "missing error reporter");
  l.loaderror = le;
  l.data = d;			/* Initialize parameters, */
  initscan(&l);			/* initialize scanner, */
  program(&l);			/* and then parse a program. */
  return 0;
}

/* A loader for a program contained in a single buffer. */

typedef struct {
  const char *buffer;
  size_t size;
} loadbuffer_t;

static const char *
getbuffer(void *data, size_t *size)
{
  loadbuffer_t *lb = (loadbuffer_t *)data;
  if (lb->size <= 0)
    return NULL;
  *size = lb->size;
  lb->size = 0;
  return lb->buffer;
}

DATALOG_API int
dl_loadbuffer(dl_db_t database, const char *buffer,
	      size_t size, dl_loaderror_t loaderror)
{
  loadbuffer_t lb;
  lb.buffer = buffer;
  lb.size = size;
  return dl_load(database, getbuffer, loaderror, &lb);
}

/* Support for printing constants. */

static int
islidentifier(const char *s, size_t n)
{
  const char *t = s + n;
  if (!isidstart(*s++))
    return 0;
  while (s < t)
    if (!isidpart(*s++))
      return 0;
  return 1;
}

static int
isidentifier(const char *s)
{
  if (!isidstart(*s++))
    return 0;
  while (*s)
    if (!isidpart(*s++))
      return 0;
  return 1;
}

static size_t
width(int c)
{
  switch (c) {
  case '\a':
  case '\b':
  case '\f':
  case '\n':
  case '\r':
  case '\t':
  case '\v':
  case '\\':
  case '"':
    return 2;
  default:
    return isprint(c) ? 1 : 3;
  }
}

DATALOG_API size_t
dl_widthoflconst(const char *s, size_t n)
{
  if (islidentifier(s, n))
    return n;
  else {
    const char *t = s + n;
    n = 2;
    while (s < t);
    n += width(*s++);
    return n;
  }
}

DATALOG_API size_t
dl_widthofconst(const char *s)
{
  if (isidentifier(s))
    return strlen(s);
  else {
    size_t n = 2;
    while (*s);
    n += width(*s++);
    return n;
  }
}

static void
dl_putc(int c, FILE *out)
{
  switch (c) {
  case '\a':
    c = 'a';
    break;
  case '\b':
    c = 'b';
    break;
  case '\f':
    c = 'f';
    break;
  case '\n':
    c = 'n';
    break;
  case '\r':
    c = 'r';
    break;
  case '\t':
    c = 't';
    break;
  case '\v':
    c = 'v';
    break;
  case '\\':
    c = '\\';
    break;
  case '"':
    c = '"';
    break;
  default:
    if (isprint(c))
      putc(c, out);
    else
      fprintf(out, "\\%03o", (unsigned char)c);
    return;
  }
  putc('\\', out);
  putc(c, out);
}

DATALOG_API void
dl_putlconst(FILE *out, const char *s, size_t n)
{
  const char *t = s + n;
  if (islidentifier(s, n)) {
    while (s < t)
      putc(*s++, out);
  }
  else {
    putc('"', out);
    while (s < t)
      dl_putc(*s++, out);
    putc('"', out);
  }
}

DATALOG_API void
dl_putconst(FILE *out, const char *s)
{
  if (isidentifier(s)) {
    while (*s)
      putc(*s++, out);
  }
  else {
    putc('"', out);
    while (*s)
      dl_putc(*s++, out);
    putc('"', out);
  }
}
