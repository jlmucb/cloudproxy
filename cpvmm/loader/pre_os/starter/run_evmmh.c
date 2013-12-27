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
