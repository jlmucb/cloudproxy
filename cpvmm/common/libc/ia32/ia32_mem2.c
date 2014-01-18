/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
.686P
.MODEL FLAT, C
.CODE

externdef vmm_memset:NEAR
externdef vmm_memcpy:NEAR
externdef vmm_strlen:NEAR

PUBLIC vmm_lock_xchg_dword
PUBLIC vmm_lock_xchg_byte
*/


void
vmm_lock_xchg_dword (
                     UINT32 *dst, //ebp + 8
                     UINT32 *src  //ebp + 12
                    )
{
/*
    push    ebx
    mov     ebx, [ebp + 12] # copy src to ebx
    lock    xchg [ebp + 8], ebx
    pop     ebx
    ret
 */
}


void
vmm_lock_xchg_byte (
                     UINT8 *dst, //ebp + 8
                     UINT8 *src  //ebp + 12
                    )
{
/*
    push ebx
    mov bl, byte ptr [ebp + 12] # copy src to bl
    lock xchg byte ptr [ebp + 8], bl
    pop ebx
    ret
 */
}


