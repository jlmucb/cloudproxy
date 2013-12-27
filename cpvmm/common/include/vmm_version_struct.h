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

#ifndef _VMM_VERSION_STRUCT_H_
#define _VMM_VERSION_STRUCT_H_

///////////////////////////////////////////////////////////////////////////////
//
// Version string is generated as an ASCII string that resides between
//  header and trailer:
//
// VERSION_START:<version-string>:VERSION_END\0
//
///////////////////////////////////////////////////////////////////////////////

#if defined DEBUG || defined ENABLE_RELEASE_VMM_LOG
// This is done to remove out the strings from the release build
#define VMM_VERSION_START "UVMM_VERSION_START:"
#define VMM_VERSION_END   ":UVMM_VERSION_END"
#else
#define VMM_VERSION_START "START"
#define VMM_VERSION_END   "END"
#endif

#endif

