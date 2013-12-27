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

#ifndef _VE_H
#define _VE_H

typedef struct _VE_INFO
{
	UINT32	exit_reason;
	UINT32	flag;
	UINT64	exit_qualification;
	UINT64	gla;		// guest linear address;
	UINT64	gpa;		// guest physical address;
	UINT16	eptp_index;
	UINT8	padding[6];
} VE_EPT_INFO;

BOOLEAN ve_is_hw_supported(void);
BOOLEAN ve_is_ve_enabled(GUEST_CPU_HANDLE gcpu);
BOOLEAN ve_update_hpa(GUEST_ID guest_id, CPU_ID guest_cpu_id, HPA hpa, UINT32 enable);
void ve_enable_ve(GUEST_CPU_HANDLE gcpu);
void ve_disable_ve(GUEST_CPU_HANDLE gcpu);
BOOLEAN ve_handle_sw_ve(GUEST_CPU_HANDLE gcpu, UINT64 qualification, UINT64 gla, UINT64 gpa, UINT64 view);

#endif
