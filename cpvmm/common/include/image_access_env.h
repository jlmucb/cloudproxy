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

#ifndef _IMAGE_ACCESS_ENV_H_
#define _IMAGE_ACCESS_ENV_H_

#ifdef WIN32
//  defintions for Win environment
#   include <memory.h>
#   include <malloc.h>
#   define MALLOC(__x) malloc(__x)
#   define FREE(__x)   free(__x)
#elif defined(EFI_SPECIFICATION_VERSION)
// definitions for EFI environment
#   include <EfiShellLib.h>
#   include "vmm_defs.h"
#   include "alloc_utils.h"
#   define MALLOC(__x) malloc_pool(__x)
#   define FREE(__x)   free_pool(__x)
#   define memcpy(__d, __s, __l) CopyMem(__d, __s, __l)
#elif defined(UVMM_MBR_LOADER)
// defintions for uVmm loader  environment
#   include "vmm_defs.h"
#   include "memory.h"
#   define MALLOC(__x) vmm_page_alloc(((__x) + PAGE_4KB_SIZE - 1) / PAGE_4KB_SIZE)
#   define FREE(__x)
#else
// defintions for uVmm environment
#   include "vmm_defs.h"
#   define MALLOC(__x) vmm_page_alloc(((__x) + PAGE_4KB_SIZE - 1) / PAGE_4KB_SIZE)
#   define FREE(__x)
#endif


#endif // _IMAGE_ACCESS_ENV_H_

