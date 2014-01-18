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
externdef vmm_memset:NEAR
externdef vmm_memcpy:NEAR
externdef vmm_strlen:NEAR


PUBLIC vmm_lock_xchg_qword
PUBLIC vmm_lock_xchg_byte
 */

void vmm_lock_xchg_qword (
                            UINT64 *dst, //rcx
                            UINT64 *src  //rdx
                         )
{
/*
    push r8
    mov r8, [rdx] # copy src to r8
    lock xchg [rcx], r8
    pop r8
    ret
 */
}


void vmm_lock_xchg_byte (
                     UINT8 *dst, //rcx
                     UINT8 *src  //rdx
                    )
{
/*
    push rbx
    mov bl, byte ptr [rdx] # copy src to bl
    lock xchg byte ptr [rcx], bl
    pop rbx
    ret
 */
}

