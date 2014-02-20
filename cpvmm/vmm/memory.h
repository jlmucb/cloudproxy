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


#ifndef MEMORY_H
#define MEMORY_H

VOID
ZeroMem(
  VOID*   Address,
  UINT32  Size
  );

VOID*
AllocateMemory(
  UINT32 Size
  );

VOID
PrintE820BiosMemoryMap(
  //INT15_E820_MEMORY_MAP *BiosMemoryMap
  );

VOID
InitializeMemoryManager(
    UINT64 *    HeapBaseAddress,
    UINT64 *    HeapBytes
  );

VOID
CopyMem(
  VOID *Dest,
  VOID *Source,
  UINT32 Size
  );

BOOLEAN
CompareMem(
  VOID *Source1,
  VOID *Source2,
  UINT32 Size
  );

void * evmm_page_alloc(UINT32 pages);

#endif // MEMORY_H
