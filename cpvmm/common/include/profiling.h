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

#ifndef _PROFILING_H
#define _PROFILING_H

#ifdef ENABLE_TMSL_PROFILING

#include "profiling_defs.h"

///////////////////////////////////////////////
//Definitions for tmsl profiling
///////////////////////////////////////////////

#define HANDLER_REPORT_EVENT handler_profiling_report_event
#define TMSL_PROFILING_API_ENTRY(__api_id, __caller) \
{\
    profiling_api(PROF_POSITION_ENTRY, __api_id, __caller);\
}
#define TMSL_PROFILING_API_EXIT(__api_id, __caller) \
{\
    profiling_api(PROF_POSITION_EXIT, __api_id, __caller);\
}
#define TMSL_PROFILING_FUNC_ENTRY(__func_id) \
{\
    profiling_func(PROF_POSITION_ENTRY, __func_id);\
}
#define TMSL_PROFILING_FUNC_EXIT(__func_id) \
{\
    profiling_func(PROF_POSITION_EXIT, __func_id);\
}
#define TMSL_PROFILING_VMEXIT() \
{\
    profiling_vmexit();\
}
#define TMSL_PROFILING_MEMORY_ALLOC(__addr, __size, __context) \
{\
    profiling_memory(__addr, __size, PROF_MEM_ACTION_ALLOC, __context);\
}
#define TMSL_PROFILING_MEMORY_FREE(__addr, __context) \
{\
    profiling_memory(__addr, 0, PROF_MEM_ACTION_FREE, __context);\
}
#define TMSL_PROFILING_INIT(__cpu_num) \
{\
    tmsl_profiling_init(__cpu_num);\
}

void tmsl_profiling_init(UINT16 cpu_num);
void handler_profiling_report_event(void *p_event_info);
void profiling_memory(UINT64 addr, UINT64 size, PROF_MEM_ACTION_TYPE type, PROF_MEM_CONTEXT_TYPE context);
void profiling_vmexit(void);
void profiling_api(PROF_POSITION_TYPE position, UINT32 api_id, PROF_API_CALLER_TYPE caller);
void profiling_func(PROF_POSITION_TYPE position, UINT32 func_id);
void profiling_custom_tag(UINT32 tag);

#else

#define TMSL_PROFILING_API_ENTRY(__api_id, __caller)
#define TMSL_PROFILING_API_EXIT(__api_id, __caller)
#define TMSL_PROFILING_FUNC_ENTRY(__func_id)
#define TMSL_PROFILING_FUNC_EXIT(__func_id)
#define TMSL_PROFILING_VMEXIT()
#define TMSL_PROFILING_MEMORY_ALLOC(__addr, __size, __context)
#define TMSL_PROFILING_MEMORY_FREE(__addr, __context)
#define TMSL_PROFILING_INIT(__cpu_num)
#endif


#endif //_PROFILING_H
