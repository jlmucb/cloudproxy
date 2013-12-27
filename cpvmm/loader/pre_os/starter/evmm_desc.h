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
* Copyright 2013 Intel Corporation All Rights Reserved.
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

// Loader.bin file header

#pragma pack(1)
typedef struct {
    UINT32 struct_size;
    UINT32 version;
    UINT32 size_in_sectors;
    UINT32 umbr_size;
    UINT32 evmm_mem_in_mb;
    UINT32 guest_count;
    UINT32 evmml_start;
    UINT32 evmml_count;
    UINT32 starter_start;
    UINT32 starter_count;
    UINT32 evmmh_start;
    UINT32 evmmh_count;
    UINT32 startap_start;
    UINT32 startap_count;
    UINT32 evmm_start;
    UINT32 evmm_count;
    UINT32 startup_start;
    UINT32 startup_count;
    UINT32 guest1_start;
    UINT32 guest1_count;
} EVMM_DESC;
#pragma pack()

// Loader memory map

#define LOADER_BIN_SIZE(td) ((td->guest1_start + td->guest1_count) * 512)
#define STATES0_BASE(td) ((UINT32)td + LOADER_BIN_SIZE(td))
#define STATES1_BASE(td) (STATES0_BASE(td) + 0x400)
#define LOADER_BASE(td) ((STATES1_BASE(td) + 0x400 + 0xfff) & 0xfffff000)
#define LOADER_SIZE (0x100000)
#define HEAP_BASE(td) (LOADER_BASE(td) + LOADER_SIZE)
#define HEAP_SIZE (0x100000)

// eVmm and thunk memory map
#define EVMM_BASE(td) (HEAP_BASE(td) + HEAP_SIZE)
#define EVMM_SIZE(td) (td->evmm_mem_in_mb * 0x100000)
#define THUNK_BASE(td) (EVMM_BASE(td) + EVMM_SIZE(td))
#define THUNK_SIZE (0x5000)

// End of file
