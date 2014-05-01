#ifndef JLMDEBUG__H_
#define JLMDEBUG__H_

#include "bootstrap_types.h"
#include "bootstrap_string.h"
#include "bootstrap_print.h"

#define UNUSEDVAR(x) ((void)x)
#undef VMM_ASSERT
#define VMM_ASSERT(x) \
    if(x) { bprint("VMM_ASSERT\n"); LOOP_FOREVER }
#endif
