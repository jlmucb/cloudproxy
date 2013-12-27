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
