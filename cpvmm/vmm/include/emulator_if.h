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

#ifndef _EMULATOR_IF_H_
#define _EMULATOR_IF_H_

#include "vmm_defs.h"
#include "list.h"
#include "guest_cpu.h"
#include "gdt.h"
#include "hw_utils.h"
#include "vmm_globals.h"

typedef struct _EMULATOR_STATE * EMULATOR_HANDLE;
typedef struct _CPU_ARCH_STATE * CPU_ARCH_STATE;

typedef enum {
    EMUL_MMIO_GPA_ACCESS = 1,
    EMUL_MMIO_HVA_ACCESS = 2
} EMUL_MMIO_ACCESS_TYPE;

typedef VMM_STATUS (*EMUL_MMIO_HANDLER)(
    ADDRESS         addr,               // virtual address to IO
    void           *p,                  // copy to/from
    RW_ACCESS       access,             // read / write
    INT32           num_bytes,          // number bytes to transfer
    INT32          *bytes_succeeded,    // number bytes actually transferred
    void           *callee_context      // pointer to callee defined state
    );


// should not be used outside emulator. placed here for convenience :-(
typedef struct _EMU_MMIO_DESCRIPTOR {
    LIST_ELEMENT        list;
    ADDRESS             address;
    INT32               region_size;
    INT32               address_type;   // 0 - GPA, 1 - HVA, others invalid
    EMUL_MMIO_HANDLER   mmio_handler;
    EMUL_MMIO_HANDLER   write;
    void               *callee_context;
} EMU_MMIO_DESCRIPTOR;


EMULATOR_HANDLE emul_create_handle(GUEST_CPU_HANDLE guest_cpu);
void    emul_destroy_handle(EMULATOR_HANDLE handle);
void    emul_intialize(EMULATOR_HANDLE handle);
void    emul_start_guest_execution(EMULATOR_HANDLE handle);
void    emul_stop_guest_execution(EMULATOR_HANDLE handle);
BOOLEAN emul_is_running(EMULATOR_HANDLE handle);
BOOLEAN emulator_interrupt_handler(EMULATOR_HANDLE handle, VECTOR_ID vector);
void    emulator_register_handlers(EMULATOR_HANDLE handle);
BOOLEAN emul_run_single_instruction(EMULATOR_HANDLE handle);
BOOLEAN emul_state_show(EMULATOR_HANDLE p_emu);
void    emul_register_mmio_handler(
            EMULATOR_HANDLE         p_emu,
            ADDRESS                 region_address,
            unsigned                size_in_bytes,
            EMUL_MMIO_ACCESS_TYPE   addr_type,
            EMUL_MMIO_HANDLER       mmio_handler,
            void                    *callee_context
            );


/*-------------------------------------------------------*
*  FUNCTION : emulator_is_running_as_guest()
*  PURPOSE  : Used in interrupt handler
*  ARGUMENTS: void
*  RETURNS  : TRUE if guest runs emulator
*-------------------------------------------------------*/
INLINE BOOLEAN emulator_is_running_as_guest(void)
{
    return ((vmm_get_state() == VMM_STATE_RUN) && (0 != hw_read_gs()));
}




#endif // _EMULATOR_IF_H_


