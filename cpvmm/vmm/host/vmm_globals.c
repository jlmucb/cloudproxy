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

#include "vmm_globals.h"
#include "vmm_version_struct.h"
#include "vmm_dbg.h"
#include "libc.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_GLOBALS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_GLOBALS_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


// Just instaniation of global variables


VMM_STATE g_vmm_state = VMM_STATE_UNINITIALIZED;

#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
// This is done to remove out the strings from the release build
#ifdef VMM_VERSION_STRING
const char* g_vmm_version_string = VMM_VERSION_START VMM_VERSION_STRING VMM_VERSION_END;
#else
const char* g_vmm_version_string = NULL;
#endif
#else
const char* g_vmm_version_string = NULL;
#endif

void vmm_version_print( void )
{
#if 0	// version print disabled
    UINT32 global_string_length = 0;
    UINT32 header_len, trailer_len;
    UINT32 cur;

    // Version string is surrounded with VMM_VERSION_START and VMM_VERSION_END
    // VMM_VERSION_END must be followed with NULL
    if (NULL == g_vmm_version_string) {
        return;
    }

    header_len = (UINT32)vmm_strlen(VMM_VERSION_START);
    trailer_len = (UINT32)vmm_strlen(VMM_VERSION_END);

    // BEFORE_VMLAUNCH. Non-fatal error, not removing ASSERT for now.
    VMM_ASSERT((0 != header_len) && (0 != trailer_len))

    global_string_length = (UINT32)vmm_strlen(g_vmm_version_string);

    if (global_string_length <= (header_len + trailer_len)) {
        // nothing between header and trailer
        return;
    }

    // check that header and trailer match
    for (cur = 0; cur < header_len; ++cur) {
        if (g_vmm_version_string[cur] != VMM_VERSION_START[cur]) {
            // header does not match
            return;
        }
    }

    for (cur = 0; cur < trailer_len; ++cur) {
        if (g_vmm_version_string[global_string_length-trailer_len+cur] != VMM_VERSION_END[cur]) {
            // trailer does not match
            return;
        }
    }

    // if we are here - version string is ok. Print it.
    VMM_LOG(mask_anonymous, level_trace,
    "\n------------------------------------------------------------------------\n");

    VMM_LOG(mask_anonymous, level_trace, "%*s\n",
            global_string_length - header_len - trailer_len,
            g_vmm_version_string + header_len);

    VMM_LOG(mask_anonymous, level_trace,
    "------------------------------------------------------------------------\n\n");
#endif
}


