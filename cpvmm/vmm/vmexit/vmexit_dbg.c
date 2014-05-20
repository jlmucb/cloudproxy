/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vmm_defs.h>
#include <guest_cpu.h>
#include <libc.h>
#include <vmm_dbg.h>
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_DBG_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_DBG_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#pragma warning (disable : 4100) // enable non referenced formal parameters

// External declaration.
//extern void gdb_check_halt(GUEST_CPU_HANDLE  gcpu);               // Checks GDB halt condition.

const char* string = "bla bla";

#define CTRL(__char)    (__char - 'a' + 1)

#define REQUEST_COUNT    8
static char monitor_requested[REQUEST_COUNT] = { 0,0,0,0,0,0,0,0};
static char monitor_request_keys[REQUEST_COUNT] = {
    CTRL('q'),
    CTRL('w'),
    CTRL('e'),
    CTRL('r'),
    CTRL('t'),
    CTRL('y'),
    CTRL('u'),
    CTRL('i')
};

int monitor_was_requested(char key)
{
    size_t i;
    for (i = 0; i < NELEMENTS(monitor_request_keys); ++i) {
        if (key == monitor_request_keys[i]) {
            return (int)i;
        }
    }
    return -1;
}



void vmexit_check_keystroke(GUEST_CPU_HANDLE gcpu UNUSED)
{
    UINT8 key = vmm_getc();
    int monitor_cpu;

    switch (key) {
    case 0: // optimization
        //gdb_check_halt(gcpu);
        break;

    case 's':
    case 'S':
    	VMM_LOG(mask_anonymous, level_trace,"%s\n", string);
    	break;

    case CTRL('b'):
    case CTRL('d'):
        VMM_DEADLOOP();
        break;

#ifdef ENABLE_VTLB
    case '`':
        IVtlbDoPerfCommand(0, VTLB_PERF_COMMAND_PRINT);
        IVtlbDoPerfCommand(0, VTLB_PERF_COMMAND_START);
        break;
#endif
    default:
        monitor_cpu = monitor_was_requested(key);
        if (monitor_cpu != -1) {
            monitor_requested[monitor_cpu] = 1;
        }
        if (monitor_requested[hw_cpu_id()] != 0) {
            monitor_requested[hw_cpu_id()] = 0;
            VMM_DEADLOOP();
        }
        break;
    }
}

