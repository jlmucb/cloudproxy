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

/*---------------------------------------------------*
*
* file      : x32_init64.h
* purpose   : jump to 64-bit execution mode
*
*----------------------------------------------------*/

#ifndef _X32_INIT64_H_
#define _X32_INIT64_H_

#include "ia32_defs.h"

typedef struct _INIT32_STRUCT {
    UINT32      i32_low_memory_page;// address of page in low memory, used for AP bootstrap
    UINT16      i32_num_of_aps;     // number of detected APs (Application Processors)
    UINT16      i32_pad;
    UINT32      i32_esp[1];          // array of 32-bit SPs (SP - top of the stack)
} INIT32_STRUCT;

typedef struct _INIT64_STRUCT {
    UINT16      i64_cs;         // 64-bit code segment selector
    IA32_GDTR   i64_gdtr;       // still in 32-bit format
    UINT64      i64_efer;       // EFER minimal required value
    UINT32      i64_cr3;        // 32-bit value of CR3
} INIT64_STRUCT;




void x32_init64_setup(void);

void x32_init64_start(
    INIT64_STRUCT *p_init64_data,
    UINT32 address_of_64bit_code,
    void * arg1,
    void * arg2,
    void * arg3,
    void * arg4);


#endif // _X32_INIT64_H_


