/*
 * Defines the C API for a library containing a small Datalog
 * interpreter.
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

#if !defined DATALOG_H
#define DATALOG_H

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined DATALOG_API
#define DATALOG_API extern
#endif

/* The object manipulated by functions in the API. */
typedef lua_State *dl_db_t;

/* A list of answers--the structure returned by dl_ask. */
typedef struct dl_answers *dl_answers_t;

/* Create a Datalog database. */
DATALOG_API dl_db_t dl_open(void);

/* Initialize a database.  Used when a database structure exists that
   lacks Datalog specific initializations.  This initialization is one
   of the actions performed by dl_open. */
DATALOG_API int dl_init(dl_db_t db);

/* Dispose a database and all its associated resources. */
DATALOG_API void dl_close(dl_db_t db);

/* Return package name and version information. */
DATALOG_API const char *dl_version(void);

/* There are two ways to build literals and clauses, and assert and
   retract clauses.  The low-level interface builds items by pushing
   each of its component on a stack, and then inserting it into the
   result.  Using this interface requires great care.

   If space permits, consider using the high-level, Datalog program
   loader provided by function dl_load.  It is implemented on top of
   the low-level interface.  The high-level interface is described in
   the Datalog User Manual. */

/* The remaining int returning functions in this interface return zero
   on success, unless othewise noted.  The maximum size of the stack
   manipulated by the functions is four, but implementations may
   provide a larger stack. */

/* Strings */

/* Push a string on the top of the stack.  The string may contain
   zeros. */
DATALOG_API int dl_pushlstring(dl_db_t db, const char *s, size_t n);

/* Push a string on the top of the stack.  The string must be zero
   terminated. */
DATALOG_API int dl_pushstring(dl_db_t db, const char *s);

/* Concatenate two strings.  Pops two strings off the top of the stack
   and then pushes the concatenation of the two strings on the top of
   the stack. */
DATALOG_API int dl_concat(dl_db_t db);

/* Literals */

/* Starts a literal.  Pushes an incompleted literal on the top of the
   stack. */
DATALOG_API int dl_pushliteral(dl_db_t db);

/* Predicate Symbols */

/* Make a string and then use this to add a predicate symbol to a
   literal.  Pops the string from stack.  For each literal, this must
   be done once, and can be done after some number of terms have been
   added. */
DATALOG_API int dl_addpred(dl_db_t db);

/* Terms */

/* Make a string and then use this to add a variable to the list of
   terms of a literal.  Pops the string from stack. */
DATALOG_API int dl_addvar(dl_db_t db);

/* Make a string and then use this to add a constant to the list of
   terms of a literal.  Pops the string from stack. */
DATALOG_API int dl_addconst(dl_db_t db);

/* Finish making a literal after adding all terms and one predicate
   symbol.  Leaves a completed literal on the top of the stack. */
DATALOG_API int dl_makeliteral(dl_db_t db);

/* Clauses */

/* Make a literal and then use this to start a clause.  Pops a
   literal from the stack and leaves a newly created, incomplete
   clause on top of the stack.  The head of the clause is the
   literal. */
DATALOG_API int dl_pushhead(dl_db_t db);

/* Make a literal and then use this to add it to the clause's body.
   Pops a literal from the stack, and inserts it into the incomplete
   clause on the top of the stack. */
DATALOG_API int dl_addliteral(dl_db_t db);

/* Finish the clause.  Leaves a completed clause on the top of the
   stack. */
DATALOG_API int dl_makeclause(dl_db_t db);

/* Actions */

/* Asserts the clause on the top of the stack.  The clause is added to
   the database and popped off the stack.  Returns -1 when a clause is
   not safe. */
DATALOG_API int dl_assert(dl_db_t db);

/* Retracts the clause on the top of the stack.  The clause is removed
   from the database and popped off the stack. */
DATALOG_API int dl_retract(dl_db_t db);

/* Computes a list that contains all ground instances of a literal
   that are a logical consequence of the clauses stored in the
   database.  Pops the literal from the stack and returns a freshly
   allocated list of answers via the a paramater, or the null pointer
   when there are errors or no answers. */
DATALOG_API int dl_ask(dl_db_t db, dl_answers_t *a);

/* Frees the space associated with a list of answers. */
DATALOG_API void dl_free(dl_answers_t a);

/* Answers */

/* Gets the predicate associated with the answers.  If the length of
   the predicate is n, n + 1 character locations are returned, and the
   last location is zero.  Other character locations in the predicate
   may be zero.  This function returns the null pointer if given
   it. */
DATALOG_API char *dl_getpred(dl_answers_t a);

/* Gets the length of the predicate associated with the answers.
   Returns zero if given the null pointer. */
DATALOG_API size_t dl_getpredlen(dl_answers_t a);

/* Gets the arity of the predicate associated with the answers.
   Returns zero if given the null pointer. */
DATALOG_API size_t dl_getpredarity(dl_answers_t a);

/* Gets the constant associated with term j in answer i.  Zero-based
   indexing is used throughout.  If the length of the constant is n,
   n + 1 character locations are returned, and the last location is
   zero.  Other character locations in the constant may be zero.  If
   there is no specified term or no answers at all, the null pointer
   is returned. */
DATALOG_API char *dl_getconst(dl_answers_t a, int i, int j);

/* Gets the length of the constant associated term j in answer i.  the
   jth term.  Zero-based indexing is used throughout.  If there is no
   jth term in the ith answer, or no answers at all, zero is
   returned. */
DATALOG_API size_t dl_getconstlen(dl_answers_t a, int i, int j);

/* Pop an item from the stack. */
DATALOG_API int dl_pop(dl_db_t db);

/* Returns the height of the stack.  For this function, the return
   value does not indicate success or failure. */
DATALOG_API int dl_mark(dl_db_t db);

/* Resets the height of the stack to a value returned by dl_mark. */
DATALOG_API int dl_reset(dl_db_t db, int m);

/* Datalog loader using a Prolog-like syntax. */

/* A reader used to supply buffers to the loader.  When called by the
   loader, the reader is given the data supplied to the loader as its
   first argument.  If there is no more input available, the reader
   returns a null pointer, otherwise it assigns the size of the buffer
   to the size parameter, and then returns a pointer to the buffer. */
typedef const char *(*dl_reader_t)(void *data, size_t *size);

/* A function used to report errors generated by the loader.  When a
   loader error occurs, this function is called with the data supplied
   to the loader, the location of the error as a line number and
   column number, and an error message. */
typedef void (*dl_loaderror_t)(void *data, int lineno, int colno,
			       const char *msg);

/* A loader for Datalog programs.  It uses a reader to obtain a
   sequence of buffers that contain the program.  The load error
   reporter is invoked when the loader detects an error, and then a
   non-zero value is returned. */
DATALOG_API int dl_load(dl_db_t database, dl_reader_t reader,
			dl_loaderror_t loaderror, void *data);

/* A loader for a program contained in a single buffer. */
DATALOG_API int dl_loadbuffer(dl_db_t database, const char *buffer,
			      size_t size, dl_loaderror_t loaderror);

/* Support for printing using the loader's syntax for constants. */

/* Print a constant of a given length.  The function assumes the
   constant has n + 1 character locations, and the last location is
   zero.  Other character locations in the constant may be zero.  */
DATALOG_API void dl_putlconst(FILE *out, const char *s, size_t n);

/* Print a zero terminated constant. */
DATALOG_API void dl_putconst(FILE *out, const char *s);

/* Determine the columns needed for a constant with a given length.
   The function assumes the constant has n + 1 character locations,
   and the last location is zero.  Other character locations in the
   constant may be zero.  */
DATALOG_API size_t dl_widthoflconst(const char *s, size_t n);

/* Determine the columns needed for a zero terminated constant. */
DATALOG_API size_t dl_widthofconst(const char *s);

#ifdef __cplusplus
}
#endif

#endif
