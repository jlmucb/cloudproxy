/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "libc_internal.h"
//#include "hw_utils.h"
#include "hw_interlocked.h"
#include "vmcall.h"
#include "emulator_if.h"
#include "host_memory_manager_api.h"
#include "vmm_globals.h"
#include "vmm_serial.h"


extern int CLI_active(void);
////////////////////////////////////////////////////////////////////////////////
//
// C-written CRT routines should be put here
//
////////////////////////////////////////////////////////////////////////////////

#define PRINTF_BUFFER_SIZE  512

#ifdef VMM_DEBUG_SCREEN
#define SCREEN_MAX_ROWS      49  // There are actually 50, but we start to count from 0
#define SCREEN_MAX_COLOUMNS  80

#define SCREEN_VGA_BASE_ADDRESS 0xB8000

static UINT8  *screen_cursor = (UINT8*)SCREEN_VGA_BASE_ADDRESS;
#endif

static UINT32  printf_lock = 0;   // Used to guard the print function.
                                  // 0         : not locked
                                  // 1 or more : locked


//
//-------------- Internal functions ----------------------
//


//===================== raw_lock(), raw_unlock() ===============================
//
// These functions are used for doing lock/unlock
// without CPU identification/validation
// The reason is to have the lock facility at the stage when cpu ID is unknown
// e.g. for LOGs at the bootstrap time
//
//==============================================================================
static
void raw_lock(volatile UINT32 *p_lock_var)
{
    UINT32 old_value;


    for (;;)
    {
        // Loop until the successfully incremented the lock variable
        // from 0 to 1 (i.e., we are the only lockers

        old_value = hw_interlocked_compare_exchange((INT32 *)p_lock_var,
                                                    0,   // Expected
                                                    1);  // New
        if (0 == old_value)
            break;
        hw_pause();
    }
}

static
void raw_force_lock(volatile UINT32 *p_lock_var)
{
    INT32 old_value;


    for (;;)
    {
        // Loop until successfully incremented the lock variable

        old_value = *p_lock_var;
        if (old_value ==
                hw_interlocked_compare_exchange((INT32 *)p_lock_var,
                                                old_value,       // Expected
                                                old_value + 1))  // New
            break;
        hw_pause();
    }
}

static
void raw_unlock(volatile UINT32 *p_lock_var)
{
    INT32 old_value;


    for (;;)
    {
        // Loop until successfully decremented the lock variable

        old_value = *p_lock_var;
        if (old_value ==
                hw_interlocked_compare_exchange((INT32 *)p_lock_var,
                                                old_value,       // Expected
                                                old_value - 1))  // New
            break;
        hw_pause();
    }
}


//==============================================================================
//
// Generic Debug Port Static Variables
//
//==============================================================================

static VMM_DEBUG_PORT_TYPE       debug_port_type = VMM_DEBUG_PORT_NONE;
static VMM_DEBUG_PORT_VIRT_MODE  debug_port_virt_mode = VMM_DEBUG_PORT_VIRT_NONE;
static void                     *debug_port_handle = NULL;


//=============================================================================
//
// Generic Debug Port Functions
//
//=============================================================================

//=============================================================================

BOOLEAN vmm_debug_port_init_params(const VMM_DEBUG_PORT_PARAMS *p_params)

{
    BOOLEAN err = FALSE;
    UINT16  debug_port_io_base = VMM_DEBUG_PORT_SERIAL_IO_BASE_DEFAULT;


    debug_port_handle = NULL;
    debug_port_type = VMM_DEBUG_PORT_SERIAL;
    debug_port_virt_mode = VMM_DEBUG_PORT_VIRT_HIDE;

    if (p_params)
    {
        // Valid parameters structure, use it

        // Only a serial debug port is currently supported.  Furtheremore,
        // only I/O-based serial port is supported.

        if (p_params->type == VMM_DEBUG_PORT_SERIAL)
        {
            debug_port_type = (VMM_DEBUG_PORT_TYPE)p_params->type;

            switch (p_params->ident_type)
            {
                case VMM_DEBUG_PORT_IDENT_IO:
                    debug_port_io_base = p_params->ident.io_base;
                    break;

                case VMM_DEBUG_PORT_IDENT_DEFAULT:
                    debug_port_io_base = VMM_DEBUG_PORT_SERIAL_IO_BASE_DEFAULT;
                    break;

                default:
                    debug_port_io_base = VMM_DEBUG_PORT_SERIAL_IO_BASE_DEFAULT;
                    err = TRUE;
            }

            debug_port_virt_mode = (VMM_DEBUG_PORT_VIRT_MODE)p_params->virt_mode;
        }

        else
        {
            // No debug port

            debug_port_type = VMM_DEBUG_PORT_NONE;
            debug_port_virt_mode = VMM_DEBUG_PORT_VIRT_NONE;
        }
    }

    if (debug_port_type == VMM_DEBUG_PORT_SERIAL)
        debug_port_handle = vmm_serial_new(debug_port_io_base,
                                           UART_PROG_IF_DEFAULT,
                                           UART_HANDSHAKE_DEFAULT);

    return err;
}


//=============================================================================

static
void vmm_debug_port_init(void)
{
    if (debug_port_type == VMM_DEBUG_PORT_SERIAL)
        vmm_serial_init(debug_port_handle);
}

//=============================================================================


void vmm_debug_port_clear(void)
{
    if (debug_port_type == VMM_DEBUG_PORT_SERIAL)
            vmm_serial_reset(debug_port_handle);
}


//=============================================================================
//
// Debug port info accessors
//
//=============================================================================

static
VMM_DEBUG_PORT_TYPE vmm_debug_port_get_type(void)

{
    return debug_port_type;
}

VMM_DEBUG_PORT_VIRT_MODE vmm_debug_port_get_virt_mode(void)

{
    return debug_port_virt_mode;
}

UINT16   // If the debug port uses an I/O range, returns its base address.
         // Otherwise, returns 0
vmm_debug_port_get_io_base(void)

{
    UINT16 io_base = 0;
    UINT16 io_end = 0;


    if (debug_port_type == VMM_DEBUG_PORT_SERIAL)
        vmm_serial_get_io_range(debug_port_handle, &io_base, &io_end);

    return io_base;
}

UINT16   // If the debug port uses an I/O range, returns its end address.
         // Otherwise, returns 0
vmm_debug_port_get_io_end(void)

{
    UINT16 io_base = 0;
    UINT16 io_end = 0;


    if (debug_port_type == VMM_DEBUG_PORT_SERIAL)
        vmm_serial_get_io_range(debug_port_handle, &io_base, &io_end);

    return io_end;
}


//======================= vmm_debug_port_*_mux() ================================
//
// Multiplexers to debug port, according to its type (none, serial etc.).
//

static
UINT8 vmm_debug_port_getc(void)
{
    if (vmm_debug_port_get_type() == VMM_DEBUG_PORT_SERIAL)
        return vmm_serial_getc(debug_port_handle);

    else
        return 0;
}

static
UINT8 vmm_debug_port_putc_nolock( UINT8 Char )
{
    if (vmm_debug_port_get_type() == VMM_DEBUG_PORT_SERIAL)
        return vmm_serial_putc_nolock(debug_port_handle, Char);

    else
        return Char;
}

static
UINT8 vmm_debug_port_putc( UINT8 Char )
{
    if (vmm_debug_port_get_type() == VMM_DEBUG_PORT_SERIAL)
        return vmm_serial_putc(debug_port_handle, Char);

    else
        return Char;
}

static
int vmm_debug_port_puts_direct(BOOLEAN is_locked, const char *string)
{
    int ret = 1;


    if (vmm_debug_port_get_type() == VMM_DEBUG_PORT_SERIAL)
    {
        if (is_locked)
        {
            // Print using the regular function

            ret = vmm_serial_puts(debug_port_handle, string);
        }

        else
        {
            // Force lock, so that regular (locked) prints will not interfere
            // until we're done.  Note that here we may interfere with ongoing
            // regular prints - but this is the nature of "nolock".

            raw_force_lock(&printf_lock);

            // Print using the "nolock" function

            ret = vmm_serial_puts_nolock(debug_port_handle, string);

            // Unlock

            raw_unlock(&printf_lock);
        }
    }

    return ret;
}


//======================= vmm_debug_port_puts() ================================
//
// Writes a string to the debug port, according to its type (none, serial etc.).
// Takes care of the case where running as guest
//

static
int vmm_debug_port_puts(BOOLEAN is_locked, const char *string)
{
    int ret = 1;


    if (emulator_is_running_as_guest())
        hw_vmcall(VMCALL_EMULATOR_PUTS, (void*)string, 0, 0);

    else
        ret = vmm_debug_port_puts_direct(is_locked, string);

    return ret;
}


//==============================================================================
//
// Emulator debug support functions
//
//==============================================================================
#ifdef DEBUG
#pragma warning(push)
#pragma warning(disable : 4100)  // Supress warnings about unreferenced formal parameter
static
VMM_STATUS vmm_io_vmcall_puts_handler(
    GUEST_CPU_HANDLE    gcpu UNUSED,
    ADDRESS            *arg1,
    ADDRESS            *arg2 UNUSED,
    ADDRESS            *arg3 UNUSED)
{
    const char *string = (const char *)*arg1;


    raw_lock(&printf_lock);

    vmm_debug_port_puts_direct(TRUE, string);

    raw_unlock(&printf_lock);

    return VMM_OK;
}
#pragma warning(pop)
#endif

//==============================================================================
//
// Generic I/O Functions
//
//==============================================================================

static
void printf_init( void )
{
}


static
int vmm_printf_int(BOOLEAN     use_lock,
                   char       *buffer,
                   UINT32      buffer_size,
                   const char *format,
                   va_list     args )
{
    UINT32  printed_size = 0;


    if (use_lock)
    {
        raw_lock(&printf_lock);
    }

    printed_size = vmm_vsprintf_s (buffer, buffer_size, format, args);

    if (printed_size && (printed_size != UINT32_ALL_ONES))
    {
        printed_size = vmm_debug_port_puts(use_lock, buffer);
    }

    if (use_lock)
    {
        raw_unlock(&printf_lock);
    }

    return printed_size;
}


static
int CDECL vmm_printf_nolock_alloc_buffer(const char *format, va_list args)
{
    // use buffer on the stack
    char buffer[PRINTF_BUFFER_SIZE];

    return vmm_printf_int ( FALSE, buffer, PRINTF_BUFFER_SIZE, format, args);
}


#ifdef VMM_DEBUG_SCREEN
static
void vmm_printf_screen_int(char* buffer,
                           UINT32 buffer_size,
                           const char *format,
                           va_list args) {
    UINT32  printed_size = 0;

    raw_lock(&printf_lock);
    printed_size = vmm_vsprintf_s (buffer, buffer_size, format, args);

    if (printed_size && (printed_size != UINT32_ALL_ONES))
    {
        UINT32 i;
        for (i = 0 ; buffer[i] != 0 ; i++)
        {
            if (buffer[i] == '\n')
            {
                UINT64 line_number;

                line_number = ((UINT64)screen_cursor - SCREEN_VGA_BASE_ADDRESS) / (SCREEN_MAX_COLOUMNS*2);
                line_number++;
                screen_cursor = (UINT8*)(line_number * SCREEN_MAX_COLOUMNS * 2) + SCREEN_VGA_BASE_ADDRESS;
            }
            else
            {
                *screen_cursor = buffer[i];
                screen_cursor += 2;
            }
        }
    }
    raw_unlock(&printf_lock);
}
#endif


//
//-------------- Interface functions ----------------------
//

void vmm_io_init( void )
{
    vmm_debug_port_init();

    printf_init();
}

int vmm_puts_nolock(const char *string )
{
    int ret = 1;


    ret = vmm_debug_port_puts(FALSE, string);

    // According to the spec, puts always ends with new line

    if (ret != EOF)
        vmm_debug_port_puts(FALSE,  "\n\r");

    return ret;
}


int vmm_puts(const char *string )
{
    int ret = 1;


    raw_lock(&printf_lock);

    ret = vmm_debug_port_puts(TRUE, string);

    // According to the spec, puts always ends with new line

    if (ret != EOF)
        vmm_debug_port_puts(TRUE,  "\n\r");

    raw_unlock(&printf_lock);

    return ret;
}


UINT8 vmm_getc(void)
{
	if (CLI_active())
	    return vmm_debug_port_getc();
	else
		return 0;
}

UINT8 vmm_putc_nolock( UINT8 Char )
{
    Char = vmm_debug_port_putc_nolock(Char);

    return Char;
}


UINT8 vmm_putc( UINT8 Char )
{
    raw_lock(&printf_lock);

    Char = vmm_debug_port_putc(Char);

    raw_unlock(&printf_lock);

    return Char;
}


int CDECL vmm_vprintf(const char *format, va_list args)
{
    // use static buffer to save stack space

    static char buffer[PRINTF_BUFFER_SIZE];

    if (emulator_is_running_as_guest())
    {
        // To avoid deadlocks use nolock version in guest environment.
        // This will eventually do a VMCALL that will use the locked
        // printf.

        return vmm_printf_nolock_alloc_buffer(format, args);
    }
    else
    {
        return vmm_printf_int(TRUE, buffer, PRINTF_BUFFER_SIZE, format, args);
    }
}


int CDECL vmm_printf( const char *format, ... )
{
    va_list args;

    va_start (args, format);

    return vmm_vprintf(format, args);
}

#ifdef DEBUG
// printf without taking any locks - use from NMI handlers
int CDECL vmm_printf_nolock(const char *format, ...)
{
    va_list args;

    va_start (args, format);

    return vmm_printf_nolock_alloc_buffer(format, args);
}

void vmm_io_emulator_register( GUEST_ID guest_id )
{
    vmcall_register( guest_id,
                     VMCALL_EMULATOR_PUTS,
                     (VMCALL_HANDLER)vmm_io_vmcall_puts_handler,
                     FALSE );
}
#endif

#ifdef VMM_DEBUG_SCREEN
void CDECL vmm_printf_screen( const char *format, ... )
{
    static char buffer[PRINTF_BUFFER_SIZE];

    va_list args;

    va_start (args, format);

    vmm_printf_screen_int(buffer, PRINTF_BUFFER_SIZE, format, args);
}


void CDECL vmm_clear_screen(void)
{
    UINT32 i;
    for (screen_cursor = (UINT8*)SCREEN_VGA_BASE_ADDRESS, i = 0;
         i < SCREEN_MAX_COLOUMNS*SCREEN_MAX_ROWS;
         screen_cursor+=2, i++)
    {
        *screen_cursor = ' ';
    }
    screen_cursor = (UINT8*) SCREEN_VGA_BASE_ADDRESS;
}
#endif

//------------------------------------------------------------------------------
//
// Test function, active only if #ifdef'ed in

#pragma warning(push)
#pragma warning(disable : 4100)  // Supress warnings about unreferenced formal parameter
void vmm_print_test(UINT32 id UNUSED)

{
#ifdef VMM_PUT_TEST
    UINT32 i;


    for (i = 0; i < 200; i++)
    {
        switch (((hw_rdtsc() / 31) + id) & 0x7)
        {
            case 0:
                vmm_printf(       "[%02d] %06d 0 l\n", id, i);   // Short, should fit in Tx FIFO
                break;

            case 1:
                vmm_printf(       "[%02d] %06d 1 l  : The Quick Brown Fox Jumps Over The Lazy Dog\n", id, i);
                break;

            case 2:
                vmm_printf(       "[%02d] %06d 2 l  : 0123456789 abcdefghijklmnopqrstuvwxyz\n", id, i);
                break;

            case 3:
                vmm_printf(       "[%02d] %06d 3 l  : the quick brown fox jumps over the lazy dog\n", id, i);
                break;

            case 4:
                vmm_printf(       "[%02d] %06d 4 l  : 0123456789 abcdefghijklmnopqrstuvwxyz\n", id, i);
                break;

            case 5:
                vmm_printf_nolock("{%02d}_%06d_5_NL\n", id, i);   // Short, should fit in Tx FIFO
                break;

            case 6:
                vmm_printf_nolock("{%02d}_%06d_6_NL_:_THE_QUICK_BROWN_FOX_JUMPS_OVER_THE_LAZY_DOG\n", id, i);
                break;

            default:
                vmm_printf_nolock("{%02d}_%06d_7_NL_:_0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n", id, i);
        }
    }
#endif
}
#pragma warning(pop)


