/*
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
 */


void hw_fnstsw (UINT16* loc)
// Read FPU status word
//   this doesnt seem to be called
{
    asm volatile(
        "\tmovq    %[loc], %%rax\n" \
        "\tfnstsw     [%%rax]\n"
    :
    : [loc] "m"(loc)
    :"rax");
    return;
}


void hw_fnstcw ( UINT16 * loc )
// Read FPU control word
{
    asm volatile(
        "\tmovq    %[loc], %%rax\n" \
        "\tfnstcw     [%%rax]\n"
    :
    : [loc] "m"(loc)
    :"rax");
    return;
}


void hw_fninit(void);
// Init FP Unit
{
    asm volatile(
        "fninit\n"
    : 
    :
    :);
    return;
}

