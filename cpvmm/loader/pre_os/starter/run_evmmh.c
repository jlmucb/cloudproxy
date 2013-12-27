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

#include "vmm_defs.h"
#include "vmm_arch_defs.h"
#include "pe_loader.h"
#include "evmm_desc.h"

/////////////////////////////////////////////////////////////////////////////

void *vmm_memset(void *dest, int val, UINT32 count)
{
    __asm
    {
        mov     edi, dest
        mov     eax, val
        mov     ecx, count

        cld
        rep     stosb
    }

    return dest;
}

/////////////////////////////////////////////////////////////////////////////

void *vmm_memcpy(void *dest, const void* src, UINT32 count)
{
    __asm
    {
        mov     esi, src
        mov     edi, dest
        mov     ecx, count

        cld
        rep     movsb
    }

    return dest;
}

/////////////////////////////////////////////////////////////////////////////

int run_evmmh(EVMM_DESC *td)
{
    BOOLEAN ok;
    void *img;
    void (*evmmh)(EVMM_DESC *td);

    img = (void *)((UINT32)td + td->evmmh_start * 512);

    ok = load_PE_image(
            (void *)img,
            (void *)LOADER_BASE(td),
            LOADER_SIZE,
            (UINT64 *)&evmmh
            );

    if (!ok)
        return -1;

    evmmh(td);
    return -1;
}

// End of file
