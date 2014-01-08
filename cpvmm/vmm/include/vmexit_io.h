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

#ifndef _VMEXIT_IO_H_
#define _VMEXIT_IO_H_


// define this structure to resolve the conflict below:
// an IO port is monitored by uVMM internally, as well as TMSL/Handler
// status -- not enabled yet.
typedef enum {
    NO_IO_OWNER               = 0x00,
    IO_OWNED_BY_UVMM          = 0x01, // used by uVMM internally.
    IO_OWNED_BY_TMSL          = 0x02, // used by APIs for TMSL IB/Handler
    IO_OWNED_BY_UVMM_TMSL     = IO_OWNED_BY_UVMM | IO_OWNED_BY_TMSL,
} IO_PORT_OWNER;



typedef 
BOOLEAN 
(*IO_ACCESS_HANDLER)(GUEST_CPU_HANDLE     gcpu,
                        UINT16            port_id,
                        unsigned          port_size, // 1, 2, 4
                        RW_ACCESS         access,
                        BOOLEAN           string_intr,  // ins/outs
                        BOOLEAN           rep_prefix,   // rep 
                        UINT32            rep_count,
                        //IO_PORT_OWNER   port_owner
                        void              *p_value, //gva for string I/O; otherwise hva.
                        void              *handler_context
                    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_setup()
*  PURPOSE  : Allocate and initialize IO VMEXITs related data structures,
*           : common for all guests
*  ARGUMENTS: GUEST_ID    num_of_guests
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_initialize(void
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_guest_setup()
*  PURPOSE  : Allocate and initialize IO VMEXITs related data structures for
*           : specific guest
*  ARGUMENTS: GUEST_ID    guest_id
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_guest_initialize(GUEST_ID guest_id
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_activate()
*  PURPOSE  : enables in HW IO VMEXITs for specific guest on given CPU
*           : called during initialization
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_activate(GUEST_CPU_HANDLE gcpu);


/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_handler_register()
*  PURPOSE  : Register/update IO handler for spec port/guest pair.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_id
*           : IO_ACCESS_HANDLER   handler
*           : void*               handler_context - passed as it to the handler
*  RETURNS  : status
*----------------------------------------------------------------------------*/
VMM_STATUS io_vmexit_handler_register(
    GUEST_ID            guest_id,
    IO_PORT_ID          port_id,
    IO_ACCESS_HANDLER   handler,
    void                *handler_context
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_handler_unregister()
*  PURPOSE  : Unregister IO handler for spec port/guest pair.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_id
*  RETURNS  : status
*----------------------------------------------------------------------------*/
VMM_STATUS io_vmexit_handler_unregister(
    GUEST_ID    guest_id,
    IO_PORT_ID  port_id
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_block_port()
*  PURPOSE  : Enable VMEXIT on port without installing handler.
*           : Blocking_handler will be used for such cases.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_from
*           : IO_PORT_ID          port_to
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_block_port(
    GUEST_ID    guest_id,
    IO_PORT_ID  port_from,
    IO_PORT_ID  port_to
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_transparent_handler()
*  PURPOSE  : Called to facilitate IO handlers to pass IO requests to HW, if needed
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_from
*           : IO_PORT_ID          port_to
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_transparent_handler(
    GUEST_CPU_HANDLE  gcpu,
    UINT16            port_id,
    unsigned          port_size, // 1, 2, 4
    RW_ACCESS         access,
    void              *p_value,
    void              *context   // not used
    );


#endif // _VMEXIT_IO_H_

