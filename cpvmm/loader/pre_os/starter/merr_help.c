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

typedef unsigned long UINT32;
typedef void (*func)(void);

#define copy(dst, src, cnt) \
    __asm mov esi, src \
    __asm mov edi, dst \
    __asm mov ecx, cnt \
    __asm cld \
    __asm rep movsb \

void merr_help(void)
{
    func call_loader;
    UINT32 img_addr;
    UINT32 img_size;
    UINT32 buf_addr;

    UINT32 merr_help0 = 0x01101000;
    UINT32 merr_help1 = 0x01100800;
    UINT32 boot_stub0 = 0x01100600;
    UINT32 boot_stub1 = 0x01101000;

    if (((UINT32 *)merr_help0)[0] != ((UINT32 *)merr_help1)[0])
    {
        // copy merr_help to header space
        copy(merr_help1, merr_help0, 512);
        __asm jmp merr_help1
    }

    copy(boot_stub1, boot_stub0, 512);

    img_addr =
        0x01100000 + // boot.bin loaction
        *(UINT32 *)(0x01100000 + 1024) + // bzImage size
        *(UINT32 *)(0x01100000 + 1028) + // initrd size
        0x1000 + // boot.bin header size
        0x1000; // bootstub size

    img_size =
        (((UINT32 *)img_addr)[24] + ((UINT32 *)img_addr)[25]) * 512;

    buf_addr = 0x30000000;

    copy(buf_addr, img_addr, img_size);
    call_loader = (func)(buf_addr + 0x400);
    call_loader();

    __asm jmp boot_stub1
    return;
}

// End of file
