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

#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "trial_exec.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(TRIAL_EXEC_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(TRIAL_EXEC_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

static TRIAL_DATA *trial_data[VMM_MAX_CPU_SUPPORTED]; // max phys. CPUs supported


void trial_execution_push(TRIAL_DATA *p_trial_data, SETJMP_BUFFER *p_env)
{
    CPU_ID cpu_id = hw_cpu_id();

    VMM_ASSERT(cpu_id < NELEMENTS(trial_data));

    p_trial_data->saved_env    = p_env;
    p_trial_data->error_code   = 0;
    p_trial_data->fault_vector = 0;
    p_trial_data->prev         = trial_data[cpu_id];
    trial_data[cpu_id]         = p_trial_data;
}


TRIAL_DATA *trial_execution_pop(void)
{
    TRIAL_DATA *p_last_trial;
    CPU_ID cpu_id = hw_cpu_id();

    VMM_ASSERT(cpu_id < NELEMENTS(trial_data));

    if (NULL != trial_data[cpu_id]) {
        p_last_trial = trial_data[cpu_id];
        trial_data[cpu_id] = trial_data[cpu_id]->prev;
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"Error. Attempt to Pop Empty Trial Stack\n");
        p_last_trial = NULL;
    }

    return p_last_trial;
}


TRIAL_DATA * trial_execution_get_last(void)
{
    CPU_ID cpu_id = hw_cpu_id();
    VMM_ASSERT(cpu_id < NELEMENTS(trial_data));
    return trial_data[cpu_id];
}

