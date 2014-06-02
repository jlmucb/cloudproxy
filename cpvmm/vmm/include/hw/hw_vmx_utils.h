/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _HW_VMX_UTILS_H_
#define _HW_VMX_UTILS_H_

#include "vmm_defs.h"

// wrappers for VMX instructions

void vmx_vmptrst(UINT64 *address);
int vmx_vmptrld(UINT64 *address);
int vmx_vmclear(UINT64 *address);
int vmx_vmlaunch(void);
int vmx_vmresume(void);
int vmx_vmwrite(size_t index, size_t buf);
int vmx_vmread(size_t index, size_t *buf);
int vmx_on(UINT64 *address);
void vmx_off(void);

// General note: all functions that return value return the same values
// 0 - The operation succeeded.
// 1 - The operation failed with extended status available in the
//     VM-instruction error field of the current VMCS.
// 2 - The operation failed without status available.
#if 0   // old success definitions
typedef enum _HW_VMX_RET_VALUE {
    HW_VMX_SUCCESS            = 0,
    HW_VMX_FAILED_WITH_STATUS = 1,
    HW_VMX_FAILED             = 2
} HW_VMX_RET_VALUE;
#endif

#define HW_VMX_SUCCESS 0
#define HW_VMX_FAILED_WITH_STATUS 1
#define HW_VMX_FAILED   2

#endif // _HW_VMX_UTILS_H_
