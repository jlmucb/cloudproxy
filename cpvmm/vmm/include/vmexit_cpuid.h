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

#ifndef _VMEXIT_CPUID_H_
#define _VMEXIT_CPUID_H_

#include "hw_utils.h"   // for CPUID_PARAMS

// return TRUE if instruction was executed, FAULSE in case of exception
typedef void (*CPUID_FILTER_HANDLER)(GUEST_CPU_HANDLE, CPUID_PARAMS *);

void vmexit_cpuid_guest_intialize( GUEST_ID  guest_id);

#endif // _VMEXIT_CPUID_H_
