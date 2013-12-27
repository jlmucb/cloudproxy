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
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
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

#ifndef _POOL_API_H_
#define _POOL_API_H_

#include <vmm_defs.h>
#include <heap.h>

typedef void* POOL_HANDLE;
#define POOL_INVALID_HANDLE ((POOL_HANDLE)NULL)

#ifdef INCLUDE_UNUSED_CODE
POOL_HANDLE pool_create(UINT32 size_of_single_element);

void pool_print(POOL_HANDLE pool_handle);
#endif

POOL_HANDLE assync_pool_create(UINT32 size_of_single_element);

void pool_destroy(POOL_HANDLE pool_handle);

void* pool_allocate(POOL_HANDLE pool_handle);

void pool_free(POOL_HANDLE pool_handle, void* data);

#ifdef ENABLE_VTLB
void* pool_allocate_must_succeed(POOL_HANDLE pool_handle, HEAP_ALLOC_HANDLE must_succeed_handle);

void pool_release_all_free_pages(POOL_HANDLE pool_handle);
#endif

#endif // _POOL_API_H_
