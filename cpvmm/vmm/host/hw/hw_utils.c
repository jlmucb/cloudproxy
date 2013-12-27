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

#include "vmm_defs.h"
#include "hw_utils.h"
#include "hw_interlocked.h"
#include "trial_exec.h"
#include "local_apic.h"
#include "8259a_pic.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HW_UTILS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HW_UTILS_C, __condition)

static UINT64 hw_tsc_ticks_per_second = 0;

#define IA32_DEBUG_IO_PORT   0x80


//================================== hw_stall() =============================== 
//
// Stall (busy loop) for a given time, using the platform's speaker port
// h/w.  Should only be called at initialization, since a guest OS may
// change the platform setting.

void hw_stall(UINT32 stall_usec)

{
    UINT32   count;
    for(count = 0; count < stall_usec; count ++)
        hw_read_port_8(IA32_DEBUG_IO_PORT);
}


//======================= hw_calibrate_tsc_ticks_per_second() ================= 
//
// Calibrate the internal variable holding the number of TSC ticks pers second.
// Should only be called at initialization, as it relies on hw_stall()

void hw_calibrate_tsc_ticks_per_second(void)

{
    UINT64 start_tsc;


    start_tsc = hw_rdtsc();
    hw_stall(1000);   // 1 ms
    hw_tsc_ticks_per_second = (hw_rdtsc() - start_tsc) * 1000;
}


//======================= hw_calibrate_tsc_ticks_per_second() ================= 
//
// Retrieve the internal variable holding the number of TSC ticks pers second.
// Note that, depending on the CPU and ASCI modes, this may only be used as a
// rough estimate.

UINT64 hw_get_tsc_ticks_per_second(void)

{
    return hw_tsc_ticks_per_second;
}


//========================== hw_stall_using_tsc() =============================
//
// Stall (busy loop) for a given time, using the CPU TSC register.
// Note that, depending on the CPU and ASCI modes, the stall accuracy may be
// rough.

void hw_stall_using_tsc(UINT32 stall_usec)

{
    UINT64   end_tsc;
    

    VMM_ASSERT(hw_tsc_ticks_per_second != 0);
    
    end_tsc = hw_rdtsc() + 
              ((UINT64)stall_usec * hw_tsc_ticks_per_second / (UINT64)1000000);

    while (hw_rdtsc() < end_tsc)
    {
        hw_pause();
    }
}

#ifdef INCLUDE_UNUSED_CODE
// Test for ready-to-be-accepted fixed interrupts.
BOOLEAN hw_is_ready_interrupt_exist(void)
{
    return local_apic_is_sw_enabled() ?
        local_apic_is_ready_interrupt_exist() : pic_is_ready_interrupt_exist();

//    if (local_apic_is_sw_enabled())
//    {
//        VMM_LOG(mask_anonymous, level_trace,"INTR LAPIC is SW ENABLED\n");
//        if (local_apic_is_ready_interrupt_exist())
//        {
//            VMM_LOG(mask_anonymous, level_trace,"INTR LAPIC intr WAINING\n");
//            return TRUE;
//        }
//        else
//        {
//            VMM_LOG(mask_anonymous, level_trace,"INTR LAPIC intr NO\n");
//            return FALSE;
//        }
//    }
//    else
//    {
//        VMM_LOG(mask_anonymous, level_trace,"INTR LAPIC is SW DISABLED\n");
//        if (pic_is_ready_interrupt_exist())
//        {
//            VMM_LOG(mask_anonymous, level_trace,"INTR **PIC intr WAINING\n");
//            return TRUE;
//        }
//        else
//        {
//            VMM_LOG(mask_anonymous, level_trace,"INTR **PIC intr NO\n");
//            return FALSE;
//        }
//    }
}
#endif

BOOLEAN hw_wrmsr_safe(UINT32 msr_id, UINT64 value, VECTOR_ID *fault_vector, UINT32 *error_code)
{
    BOOLEAN ret;
    TRIAL_DATA *p_trial = NULL;

    TRY {
        hw_write_msr(msr_id, value);
        ret = TRUE;
    }
    CATCH(p_trial) {
        ret = FALSE;
        if (NULL != p_trial)
        {
            VMM_LOG(mask_anonymous, level_error,"WRMSR(%P) Failed. FaultVector=%P ErrCode=%P\n",
                    msr_id, p_trial->fault_vector, p_trial->error_code);
            if (NULL != fault_vector) *fault_vector = p_trial->fault_vector;
            if (NULL != error_code) *error_code = p_trial->error_code;
        }
    }
    END_TRY;
    return ret;
}

BOOLEAN hw_rdmsr_safe(UINT32 msr_id, UINT64 *value, VECTOR_ID *fault_vector, UINT32 *error_code)
{
    BOOLEAN ret;
    TRIAL_DATA *p_trial = NULL;

    TRY {
        *value = hw_read_msr(msr_id);
        ret = TRUE;
    }
    CATCH(p_trial) {
        ret = FALSE;
        if (NULL != p_trial)
        {
            VMM_LOG(mask_anonymous, level_error,"RDMSR[%P] failed. FaultVector=%P ErrCode=%P\n",
                    msr_id, p_trial->fault_vector, p_trial->error_code);
            if (NULL != fault_vector) *fault_vector = p_trial->fault_vector;
            if (NULL != error_code) *error_code = p_trial->error_code;
        }
    }
    END_TRY;
    return ret;
}

