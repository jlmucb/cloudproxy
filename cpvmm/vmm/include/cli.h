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

#ifndef _CLI_H_
#define _CLI_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "cli_env.h"

typedef int (*CLI_FUNCTION) (unsigned argc, char *args[]);

#ifdef CLI_INCLUDE

void CLI_OpenSession(const char* reason, UINT32 access_level );
BOOLEAN CLI_CloseSession(void);
void CLI_EndSession(BOOLEAN cli_retvalue);
BOOLEAN CLI_IsSessionActive(void);
BOOLEAN CLI_IsSessionActiveOnThisCpu(void);
void CLI_PrintSessionReason(void);
int  CLI_AddCommand(CLI_FUNCTION function, char *path, char *help, char *usage, UINT32 access_level);
int  CLI_ExecCommand(char *path);
void CLI_Prompt(void);
void CLI_Init(void);
void Cli_emulator_register( GUEST_ID guest_id );
UINT32 Cli_get_level(void);
BOOLEAN Cli_set_level( UINT32 level );

#else // ! CLI_INCLUDE

#pragma warning( push )
#pragma warning( disable : 4100 )
INLINE void CLI_OpenSession(const char* reason, UINT32 access_level ){
}
INLINE BOOLEAN CLI_CloseSession(void){
    return FALSE;
}
INLINE void CLI_EndSession(BOOLEAN cli_retvalue){
}
INLINE BOOLEAN CLI_IsSessionActive(void){
    return FALSE;
}
INLINE BOOLEAN CLI_IsSessionActiveOnThisCpu(void){
    return FALSE;
}
INLINE void CLI_PrintSessionReason(void){
}
INLINE int  CLI_AddCommand(CLI_FUNCTION function, char *path, char *help, char *usage, UINT32 access_level){
	return -1;
}
INLINE int  CLI_ExecCommand(char *path) {
	return -1;
}
INLINE void CLI_Prompt(void) {
}
INLINE void Cli_emulator_register( GUEST_ID guest_id ) {
}
INLINE UINT32 Cli_get_level(void){ return 0; }
INLINE BOOLEAN Cli_set_level( UINT32 level ) {return FALSE;}
#pragma warning( pop )
#endif // CLI_INCLUDE


#if defined(__cplusplus)
}
#endif

#endif // _CLI_H_

