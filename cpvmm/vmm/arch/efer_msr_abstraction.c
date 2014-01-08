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

#include <vmm_defs.h>
#include <hw_utils.h>
#include <efer_msr_abstraction.h>
#include <em64t_defs.h>

#pragma warning( disable : 4214 )

void efer_msr_set_nxe(void) {
    IA32_EFER_S efer_reg;
    efer_reg.Uint64 = hw_read_msr(IA32_MSR_EFER);
    if (efer_reg.Bits.NXE == 0) {
        efer_reg.Bits.NXE = 1;
        hw_write_msr(IA32_MSR_EFER, efer_reg.Uint64);
    }
}

BOOLEAN efer_msr_is_nxe_bit_set(IN UINT64 efer_msr_value) {
    IA32_EFER_S efer_reg;
    efer_reg.Uint64 = efer_msr_value;
    return (efer_reg.Bits.NXE != 0);
}

UINT64 efer_msr_read_reg(void) {
    return hw_read_msr(IA32_MSR_EFER);
}
