#ifndef JLMDEBUG__H_
#define JLMDEBUG__H_

#include "bootstrap_types.h"
#include "bootstrap_string.h"
#include "bootstrap_print.h"

#define UNUSEDVAR(x) ((void)x)
#undef VMM_ASSERT
#define VMM_ASSERT(x) \
    if(!(x)) { bprint("VMM_ASSERT\n"); LOOP_FOREVER }

inline static int evmmdebugwait() 
{
    volatile UINT64 l;
    for(l=0; l<80000000000;l++);
    return l;
}
#endif
