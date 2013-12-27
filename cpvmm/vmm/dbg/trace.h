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


BOOLEAN
trace_init(
           UINT32 max_num_guests,
           UINT32 max_num_guest_cpus
           );


BOOLEAN
trace_add_record(
                 IN  UINT32  vm_index,
                 IN  UINT32  cpu_index,
                 IN  UINT32  buffer_index,
                 IN  TRACE_RECORD_DATA *data
                 );


BOOLEAN
trace_remove_oldest_record(
                           OUT UINT32            *vm_index,
                           OUT UINT32            *cpu_index,
                           OUT UINT32            *buffer_index,
                           OUT UINT32            *record_index,
                           OUT TRACE_RECORD_DATA *data
                           );


BOOLEAN
trace_lock(
           void
           );


BOOLEAN
trace_unlock(
              void
              );

void trace_set_recyclable(BOOLEAN recyclable);


#endif // TRACE_H
