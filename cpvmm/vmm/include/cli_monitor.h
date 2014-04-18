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

#ifndef _CLI_MONITOR_H_
#define _CLI_MONITOR_H_

#include "cli_env.h"

#ifdef CLI_INCLUDE

void CliMonitorInit(void);
// returns TRUE if BREAK_POINT is required
BOOLEAN CliMonitor( const char* title, UINT32 access_level );

BOOLEAN Cli_DeadloopHelper( const char* assert_condition,
             const char* func_name, const char* file_name,
             UINT32 line_num, UINT32 access_level);

// returns TRUE if VMM_BREAKPOINT is required
void Cli_HandleError( const char* assert_condition,
             const char* func_name, const char* file_name,
             UINT32 line_num, UINT32 error_level);
#else // ! CLI_INCLUDE

#pragma warning( push )
#pragma warning( disable : 4100 )

INLINE void CliMonitorInit(void){}
INLINE BOOLEAN CliMonitor( const char* title, UINT32 access_level )
        { return FALSE; }
INLINE BOOLEAN Cli_DeadloopHelper( const char* assert_condition,
                const char* func_name, const char* file_name,
                UINT32 line_num, UINT32 access_level) 
        { return TRUE; }

INLINE void Cli_HandleError( const char* assert_condition,
                const char* func_name, const char* file_name,
                UINT32 line_num, UINT32 error_level) 
        { VMM_UP_BREAKPOINT(); }

#pragma warning( pop )

#endif // CLI_INCLUDE

#endif // _CLI_MONITOR_H_

