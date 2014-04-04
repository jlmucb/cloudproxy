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

#ifndef LVMM_LOADER_H
#define LVMM_LOADER_H

#ifdef CIRT_DEBUG_DISABLED
#define PRINT_STRING(arg)
#define PRINT_VALUE(arg)
#define PRINT_STRING_AND_VALUE(String, Value)
#else
#define PRINT_STRING(arg) PrintString((UINT8*)arg)
#define PRINT_VALUE(arg)  PrintValue ((UINT32)arg)
#define PRINT_STRING_AND_VALUE(String, Value) {PRINT_STRING(String); PRINT_VALUE(Value); PRINT_STRING("\n");}
#endif

void
SetupIDT(void
  );

#endif  // LVMM_LOADER_H
