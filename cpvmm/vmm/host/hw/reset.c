/*
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
 */

#include "vmm_defs.h"
#include "hw_utils.h"
#include "common_libc.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(RESET_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(RESET_C, __condition)

#pragma warning( disable : 4214) // warning C4214: nonstandard extension used : bit field types other than int
// With the default Microsoft extensions (/Ze), bitfield structure members can be of any integer type.

#define RESET_CONTROL_REGISTER_IO_PORT         0xCF9

typedef enum {
    SystemResetBit = 1, // 0 = cpu_reset generates an INIT(Soft Reset), 1 = cpu_reset generates platform reset (Hard Reset)
    CpuResetBit    = 2, // 0->1 transition generates the reset type specified by system_reset
    FullResetBit   = 3
} RESET_CONTROL_REGISTER_BITS;

#define SET_SYSTEM_RESET( v )  BIT_SET( v, SystemResetBit )
#define CLR_SYSTEM_RESET( v )  BIT_CLR( v, SystemResetBit )
#define GET_SYSTEM_RESET( v )  BIT_GET( v, SystemResetBit )

#define SET_CPU_RESET( v )  BIT_SET( v, CpuResetBit )
#define CLR_CPU_RESET( v )  BIT_CLR( v, CpuResetBit )
#define GET_CPU_RESET( v )  BIT_GET( v, CpuResetBit )

#define SET_FULL_RESET( v )  BIT_SET( v, FullResetBit )
#define CLR_FULL_RESET( v )  BIT_CLR( v, FullResetBit )
#define GET_FULL_RESET( v )  BIT_GET( v, FullResetBit )

void hw_reset_platform(void)
{
  UINT8  reset_control_register;

  //
  // Write the ICH register required to perform a platform reset (Cold Reset)
  //
  reset_control_register = hw_read_port_8(RESET_CONTROL_REGISTER_IO_PORT);

  SET_CPU_RESET( reset_control_register );
  SET_SYSTEM_RESET( reset_control_register );

  hw_write_port_8 (RESET_CONTROL_REGISTER_IO_PORT, reset_control_register);

  //
  // Never returns
  //
  VMM_DEADLOOP ();
}

