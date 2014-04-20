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

#ifndef TRACE_H
#define TRACE_H

#include "vmm_defs.h"

#define MAX_TRACE_BUFFERS       1
#define MAX_STRING_LENGTH       128
#define MAX_RECORDS_IN_BUFFER   2048


typedef struct {
    UINT64  tsc;
    UINT64  exit_reason;
    UINT64  guest_eip;
    char    string[MAX_STRING_LENGTH];
} TRACE_RECORD_DATA;


BOOLEAN trace_init( UINT32 max_num_guests, UINT32 max_num_guest_cpus);
BOOLEAN trace_add_record( IN  UINT32  vm_index, IN  UINT32  cpu_index, IN  UINT32  buffer_index,
                 IN  TRACE_RECORD_DATA *data);
BOOLEAN trace_remove_oldest_record( OUT UINT32 *vm_index, OUT UINT32 *cpu_index,
             OUT UINT32 *buffer_index, OUT UINT32 *record_index, OUT TRACE_RECORD_DATA *data);
BOOLEAN trace_lock( void);
BOOLEAN trace_unlock( void);
void trace_set_recyclable(BOOLEAN recyclable);
#endif // TRACE_H
