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

#ifndef _VMM_OBJECTS_H_
#define _VMM_OBJECTS_H_

////////////////////////////////////////////////////////////////////////////////
//
// Typedefs of the mostly used objects
//
////////////////////////////////////////////////////////////////////////////////

typedef void*                       GPM_HANDLE;
typedef struct _GUEST_CPU *         GUEST_CPU_HANDLE;
typedef struct _GUEST_DESCRIPTOR *  GUEST_HANDLE;
typedef struct _VMCS_OBJECT         VMCS_OBJECT;
#ifdef ENABLE_AUTOVIEW_SWITCH
typedef void* GVM_HANDLE;
#endif
//typedef struct _VIRTUAL_CPU_ID      VIRTUAL_CPU_ID;

//
// Support for call from NMI exception handler
//
typedef enum _VMM_CALLING_ENVIRONMENT {
    VMM_CALL_NORMAL = 0,
    VMM_CALL_FROM_NMI_HANDLER
} VMM_CALLING_ENVIRONMENT;

#endif // _VMM_OBJECTS_H_
