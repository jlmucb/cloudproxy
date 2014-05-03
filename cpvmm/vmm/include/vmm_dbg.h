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

#pragma once
#ifndef _VMM_DBG_H_
#define _VMM_DBG_H_

#include "vmm_startup.h"
#include "heap.h"
#include "cli_monitor.h"


extern CPU_ID hw_cpu_id();
extern void ipc_set_no_resend_flag(BOOLEAN val);
extern BOOLEAN vmm_debug_port_init_params(const VMM_DEBUG_PORT_PARAMS *p_params);
extern VMM_DEBUG_PORT_VIRT_MODE vmm_debug_port_get_virt_mode(void);
extern UINT16 vmm_debug_port_get_io_base(void);// If the debug port uses an I/O range, returns its base address. -Otherwise, returns 0
extern UINT16 vmm_debug_port_get_io_end(void);// If the debug port uses an I/O range, returns its end address. - Otherwise, returns 0
extern int vmm_printf( const char *format, ...);// __attribute__((format (printf, 1,2)));
extern int vmm_vprintf(const char *format, va_list args);
#ifdef VMM_DEBUG_SCREEN
extern void vmm_printf_screen( const char *format, ...);
extern void vmm_clear_screen(void);
#endif

extern VMM_STARTUP_STRUCT vmm_startup_data;
extern void vmm_deadloop_dump(UINT32 file_code, UINT32 line_num);

BOOLEAN DeadloopHelper(const char* assert_condition, const char* func_name,
                       const char* file_name, UINT32 line_num, UINT32 access_level);

#ifdef DEBUG
#define VMM_DEBUG_CODE(__xxx) __xxx
#else
#define VMM_DEBUG_CODE(__xxx)
#endif



enum debug_bit_mask
{
    // NOTE: values should be in the range of 0 - 31
    mask_anonymous      = 0, // a temporary mask to maintain backwards compatibility. Eventually every component should create its own mask.
    mask_cli            = 1,
    mask_emulator       = 2,
    mask_gdb            = 3,
    mask_ept            = 4,
    mask_uvmm           = 5,
    mask_tmm            = 6,
    mask_tmsl           = 7,
    mask_handler        = 8
};

#define DEBUG_MASK_ALL (unsigned long long)(-1)



enum msg_level
{
    level_print_always  = 0,
    level_error         = 1,
    level_warning       = 2,
    level_info          = 3,
    level_trace         = 4
};


#define VMM_COMPILE_TIME_ADDRESS(__a) ((__a) - vmm_startup_data.vmm_memory_layout[uvmm_image].base_address)
#define VMM_RANGE_ADDRESS(__a)                                                 \
   ((__a) >= vmm_startup_data.vmm_memory_layout[uvmm_image].base_address &&    \
    (__a) < (vmm_startup_data.vmm_memory_layout[uvmm_image].base_address + vmm_startup_data.vmm_memory_layout[uvmm_image].total_size))

#define VMM_DEFAULT_LOG_MASK vmm_startup_data.debug_params.mask
#define VMM_DEFAULT_LOG_LEVEL vmm_startup_data.debug_params.verbosity


#define VMM_BREAKPOINT()                                \
{                                                       \
    ipc_set_no_resend_flag(TRUE);                       \
    VMM_UP_BREAKPOINT();                                \
}

#ifdef CLI_INCLUDE
#define VMM_DEADLOOP_HELPER Cli_DeadloopHelper
#else
#define VMM_DEADLOOP_HELPER DeadloopHelper
#endif

//JLM(FIX)
#if 0
#ifdef DEBUG
#define VMM_DEADLOOP_LOG(FILE_CODE)                                             \
{                                                                               \
    if (VMM_DEADLOOP_HELPER(NULL, __FUNCTION__, __FILE__, __LINE__, 1))          \
    {                                                                           \
        VMM_UP_BREAKPOINT();                                                    \
    }                                                                           \
}
#else 
#define VMM_DEADLOOP_LOG(FILE_CODE)	vmm_deadloop_dump(FILE_CODE, __LINE__);
#endif
#else
#define VMM_DEADLOOP_LOG(FILE_CODE)
#endif


#ifdef LOG_MASK
#define VMM_MASK_CHECK(MASK)		(((unsigned long long)1<<MASK) & LOG_MASK) && (((unsigned long long)1<<MASK) & VMM_DEFAULT_LOG_MASK)
#else
#define VMM_MASK_CHECK(MASK)		(((unsigned long long)1<<MASK) & VMM_DEFAULT_LOG_MASK)
#endif

#ifdef LOG_LEVEL
#define VMM_LEVEL_CHECK(LEVEL)		(LEVEL <= LOG_LEVEL) && (LEVEL <= VMM_DEFAULT_LOG_LEVEL)
#else
#define VMM_LEVEL_CHECK(LEVEL)		(LEVEL <= VMM_DEFAULT_LOG_LEVEL)
#endif

//JLM(FIX)
#if 0
#if defined ENABLE_RELEASE_VMM_LOG && !defined DEBUG
#define VMM_LOG(MASK,LEVEL,...) ((((LEVEL==level_print_always) || (LEVEL==level_error)) && (VMM_MASK_CHECK(MASK) && VMM_LEVEL_CHECK(LEVEL))) && (vmm_printf(__VA_ARGS__)))
#else
#define VMM_LOG(MASK,LEVEL,...) VMM_DEBUG_CODE(((LEVEL==level_print_always) || (LEVEL==level_error) || ((VMM_MASK_CHECK(MASK) && VMM_LEVEL_CHECK(LEVEL)))) && (vmm_printf(__VA_ARGS__)))
#endif
#else
#define VMM_LOG(MASK,LEVEL,...)
#endif


#ifdef VMM_DEBUG_SCREEN
#define VMM_LOG_SCREEN(...)  VMM_DEBUG_CODE(vmm_printf_screen(__VA_ARGS__))
#else
#define VMM_LOG_SCREEN(...)
#endif
#define VMM_LOG_NOLOCK(...)  VMM_DEBUG_CODE(vmm_printf_nolock(__VA_ARGS__))

//JLM(FIX)
#if 0
#ifdef DEBUG
#define VMM_ASSERT_LOG(FILE_CODE, __condition)                                  \
{                                                                               \
    if ( ! (__condition))                                                       \
    {                                                                           \
        if (VMM_DEADLOOP_HELPER(#__condition, __FUNCTION__, __FILE__, __LINE__, 1)) \
        {                                                                       \
            VMM_UP_BREAKPOINT();                                                \
        }                                                                       \
    }                                                                           \
}
#else
#define VMM_ASSERT_LOG(FILE_CODE, __condition)                                    \
{                                                                               \
	if ( ! (__condition))                                                       \
	{                                                                           \
		vmm_deadloop_dump(FILE_CODE, __LINE__);                                 \
	}                                                                           \
}
#endif
#else
#define VMM_ASSERT_LOG(FILE_CODE, __condition) 

#endif

#define VMM_ASSERT_NOLOCK_LOG(FILE_CODE, __condition)    VMM_ASSERT_LOG(FILE_CODE, __condition)

#define VMM_CALLTRACE_ENTER() VMM_LOG(mask_anonymous, level_trace, "[%d enter>>> %s\n", hw_cpu_id(), __FUNCTION__)
#define VMM_CALLTRACE_LEAVE() VMM_LOG(mask_anonymous, level_trace, "<<<leave %d] %s\n", hw_cpu_id(), __FUNCTION__)


int CLI_active(void);

/* ERROR levels used in the macros below. */
enum error_level
{
    API_ERROR             = 0,
    FATAL_ERROR           = 1,
    FATAL_ERROR_DEADLOOP  = 2
};
 

/* Depending on the error_level, it either injects an exception into the
 * guest or causes an infinite loop that never returns.
 */
#define VMM_ERROR_CHECK(__condition, __error_level)                     \
{                                                                       \
    if ( ! (__condition))                                               \
    {                                                                   \
        Cli_HandleError(#__condition, __FUNCTION__, __FILE__, __LINE__, __error_level);\
    }                                                                   \
}

#endif // _VMM_DBG_H_


