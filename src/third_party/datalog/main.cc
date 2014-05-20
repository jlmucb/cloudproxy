#include <iostream>
#include <cstdio>
#include "lua.h"
#include "datalog.h"

using namespace std;

int main(int ac, char **av)
{
	dl_db_t db = dl_open();

	// printf("datalog version %s\n", dl_version());

	// q(X) :- p(X).
	// p(a).
	// q(a)?
	// q(b)?

	dl_pushliteral(db);
	dl_pushstring(db, "q");
	dl_addpred(db);
	dl_pushstring(db, "X");
	dl_addvar(db);
	dl_makeliteral(db);

	dl_pushhead(db);

	dl_pushliteral(db);
	dl_pushstring(db, "p");
	dl_addpred(db);
	dl_pushstring(db, "X");
	dl_addvar(db);
	dl_makeliteral(db);

	dl_addliteral(db);
	dl_makeclause(db);
	dl_assert(db);

	dl_pushliteral(db);
	dl_pushstring(db, "p");
	dl_addpred(db);
	dl_pushstring(db, "a");
	dl_addconst(db);
	dl_makeliteral(db);
	dl_pushhead(db);
	dl_makeclause(db);
	dl_assert(db);

	dl_pushliteral(db);
	dl_pushstring(db, "q");
	dl_addpred(db);
	dl_pushstring(db, "a");
	dl_addconst(db);
	dl_makeliteral(db);
	dl_answers_t a;
	dl_ask(db, &a);
	if (a) {
		printf("yay, got an answer\n");
		dl_free(a);
	} else {
		printf("nope, no answers\n");
	}


	dl_close(db);
	return 0;
}
