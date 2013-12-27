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

/*
   Trace mechanism
*/

#include "trace.h"
#include "heap.h"
#include "common_libc.h"

#pragma warning( disable : 4100) // warning C4100: unreferenced formal parameter

#define CYCLIC_INCREMENT(x)   do { (x)++; if ((x) == MAX_RECORDS_IN_BUFFER) (x) = 0; } while (0)

#define NON_CYCLIC_INCREMENT(x)   do { (x)++; if ((x) == MAX_RECORDS_IN_BUFFER) (x) --; } while (0)

#define FOREACH_BUFFER(apply_function, param) \
do { \
    UINT32 vm_index = 0, cpu_index = 0, buffer_index = 0; \
    for (vm_index = 0; vm_index < trace_state->max_num_guests; vm_index++)  { \
        for (cpu_index = 0; cpu_index < trace_state->max_num_guest_cpus; cpu_index++) { \
            for (buffer_index = 0; buffer_index < MAX_TRACE_BUFFERS; buffer_index++) { \
                apply_function(vm_index, cpu_index, buffer_index, param); \
            } \
        } \
    } \
} while (0)

typedef struct {
    BOOLEAN               valid;
    UINT32                index;
    TRACE_RECORD_DATA     data;
    struct _TRACE_BUFFER *buffer;
} TRACE_RECORD;


typedef struct _TRACE_BUFFER {
    UINT32        vm_index;
    UINT32        cpu_index;
    UINT32        buffer_index;
    UINT32        next_record_index;
    TRACE_RECORD  records[MAX_RECORDS_IN_BUFFER];
} TRACE_BUFFER;

typedef struct _TRACE_STATE {
    UINT32        global_counter;
    BOOLEAN       locked;
    UINT32		  max_num_guests;
    UINT32		  max_num_guest_cpus;
    TRACE_BUFFER  buffers[1]; // pointer to buffers
} TRACE_STATE;

static BOOLEAN trace_initialized = FALSE;
static TRACE_STATE *trace_state = NULL;
static BOOLEAN trace_recyclable = TRUE;


#define GET_BUFFER(vm_index, cpu_index, buffer_index) \
    (trace_state->buffers + \
    vm_index * trace_state->max_num_guest_cpus * MAX_TRACE_BUFFERS \
    + cpu_index * MAX_TRACE_BUFFERS \
    + buffer_index)

static void
initialize_trace_buffer(
                        UINT32 vm_index,
                        UINT32 cpu_index,
                        UINT32 buffer_index,
                        void*    param  UNUSED
                        )
{
    TRACE_BUFFER *buffer;
    UINT32 record_index;

    buffer = GET_BUFFER(vm_index, cpu_index, buffer_index);

    buffer->vm_index = vm_index;
    buffer->cpu_index = cpu_index;
    buffer->buffer_index = buffer_index;

    for (record_index = 0; record_index < MAX_RECORDS_IN_BUFFER; record_index++) {
        buffer->records[record_index].valid = FALSE;
        buffer->records[record_index].buffer = buffer;
    }

    buffer->next_record_index = 0;
}

BOOLEAN
trace_init(
           UINT32 max_num_guests,
           UINT32 max_num_guest_cpus)
{
    if (trace_initialized) {
        return FALSE;
    }
    trace_state = vmm_memory_alloc(sizeof(TRACE_STATE) +
        max_num_guests * max_num_guest_cpus * MAX_TRACE_BUFFERS * sizeof(TRACE_BUFFER) - 1); // trace_state already includes one buffer
    if(NULL == trace_state)
    {
        return FALSE;
    }

    trace_state->global_counter = 0;
    trace_state->locked = FALSE;
    trace_state->max_num_guests = max_num_guests;
    trace_state->max_num_guest_cpus = max_num_guest_cpus;

    FOREACH_BUFFER(initialize_trace_buffer, NULL);

    trace_initialized = TRUE;
    return TRUE;
}

static void
add_record(
           TRACE_BUFFER      *buffer,
           TRACE_RECORD_DATA *data
           )
{
    TRACE_RECORD *record = &buffer->records[buffer->next_record_index];

    record->valid = TRUE;
    record->index = trace_state->global_counter++;

    record->data.tsc        = data->tsc;
    record->data.exit_reason = data->exit_reason;
    record->data.guest_eip   = data->guest_eip;
    vmm_strcpy_s(record->data.string, MAX_STRING_LENGTH, data->string);

    if (trace_recyclable)
        CYCLIC_INCREMENT(buffer->next_record_index);
    else
        NON_CYCLIC_INCREMENT(buffer->next_record_index);
}

BOOLEAN
trace_add_record(
                 IN  UINT32  vm_index,
                 IN  UINT32  cpu_index,
                 IN  UINT32  buffer_index,
                 IN  TRACE_RECORD_DATA *data
                 )
{
    if (!trace_initialized || trace_state->locked || data == NULL
        || vm_index >= trace_state->max_num_guests || cpu_index >= trace_state->max_num_guest_cpus
        || buffer_index >= MAX_TRACE_BUFFERS) {
            return FALSE;
    }

    add_record(GET_BUFFER(vm_index, cpu_index, buffer_index), data);

    return TRUE;
}

static void
remove_record(
              TRACE_RECORD *record
              )
{
    record->valid = FALSE;
    CYCLIC_INCREMENT(record->buffer->next_record_index);
}

static void
set_buffer_pointer_to_oldest_record(
                                    UINT32  vm_index,
                                    UINT32  cpu_index,
                                    UINT32  buffer_index,
                                    void*     param UNUSED
                                    )
{
    TRACE_BUFFER *buffer = GET_BUFFER(vm_index, cpu_index, buffer_index);

    if (!buffer->records[buffer->next_record_index].valid) {
        UINT32 i;

        for (i = 0; i < MAX_RECORDS_IN_BUFFER; i++) {
            if (buffer->records[i].valid) {
                break; // found
            }
        }
        buffer->next_record_index = (i < MAX_RECORDS_IN_BUFFER)? i: 0;
    }
}

static void
find_buffer_with_oldest_record(
                               UINT32  vm_index,
                               UINT32  cpu_index,
                               UINT32  buffer_index,
                               void   *param
                               )
{
    TRACE_RECORD **oldest_record_ptr = (TRACE_RECORD **)param;
    TRACE_BUFFER  *buffer = GET_BUFFER(vm_index, cpu_index, buffer_index);
    TRACE_RECORD  *record = &buffer->records[buffer->next_record_index];

    if (record->valid) {
        if ((*oldest_record_ptr == NULL) ||                // this record is the first record encountered
            (record->index < (*oldest_record_ptr)->index)) // this record is older than the oldest record
        {
            *oldest_record_ptr = record;
        }
    }
}

static TRACE_RECORD *
find_oldest_record(
                   void
                   )
{
    TRACE_RECORD *oldest_record = NULL;

    // find the oldest record in each buffer
    FOREACH_BUFFER(set_buffer_pointer_to_oldest_record, NULL);

    // find the globally oldest record
    FOREACH_BUFFER(find_buffer_with_oldest_record, &oldest_record);

    return oldest_record;
}

BOOLEAN
trace_remove_oldest_record(
                           OUT UINT32            *vm_index,
                           OUT UINT32            *cpu_index,
                           OUT UINT32            *buffer_index,
                           OUT UINT32            *record_index,
                           OUT TRACE_RECORD_DATA *data
                           )
{
    TRACE_RECORD *oldest_record;

    if (!trace_initialized) {
        return FALSE;
    }

    oldest_record = find_oldest_record();
    if (oldest_record == NULL) {
        return FALSE;
    }

    remove_record(oldest_record);

    if (vm_index  != NULL)    *vm_index  = oldest_record->buffer->vm_index;
    if (cpu_index != NULL)    *cpu_index = oldest_record->buffer->cpu_index;
    if (buffer_index != NULL) *buffer_index = oldest_record->buffer->buffer_index;
    if (record_index != NULL) *record_index = oldest_record->index;
    if (data != NULL) {
        data->exit_reason = oldest_record->data.exit_reason;
        data->guest_eip   = oldest_record->data.guest_eip;
        data->tsc        = oldest_record->data.tsc;
        vmm_strcpy_s(data->string, MAX_STRING_LENGTH, oldest_record->data.string);
    }

    return TRUE;
}

BOOLEAN
trace_lock(
           void
           )
{
    if (!trace_initialized || trace_state->locked) {
        return FALSE;
    }
    trace_state->locked = TRUE;
    return TRUE;
}

BOOLEAN
trace_unlock(
             void
             )
{
    if (!trace_initialized || !trace_state->locked) {
        return FALSE;
    }
    trace_state->locked = FALSE;
    return TRUE;
}

void trace_set_recyclable(BOOLEAN recyclable)
{
    trace_recyclable = recyclable;
}

