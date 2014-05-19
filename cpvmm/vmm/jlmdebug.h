#ifndef JLMDEBUG__H_
#define JLMDEBUG__H_

#include "bootstrap_types.h"
#include "bootstrap_string.h"
#include "bootstrap_print.h"

#define UNUSEDVAR(x) ((void)x)
#undef VMM_ASSERT
#define VMM_ASSERT(x) \
    if(!(x)) { bprint("VMM_ASSERT\n"); LOOP_FOREVER }

#define LONGLOOP   8000000000ULL
#define MEDIUMLOOP  800000000ULL
#define SHORTLOOP   100000000ULL

inline static int evmmdebugwait(unsigned long long limit) 
{
    volatile unsigned long long l;
    for(l=0; l<limit;l++);
    return l;
}

#if 1
#ifdef JLMDEBUG
#undef VMM_DEADLOOP
#define VMM_DEADLOOP() {bprint("Hit Deadloop\n");LOOP_FOREVER}
#endif
#endif
#endif
