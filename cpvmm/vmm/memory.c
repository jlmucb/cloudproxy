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

#include "common_libc.h"

//#undef KILOBYTE
//#undef MEGABYTE
//#undef BOOLEAN

#include <vmm_defs.h>
#include <vmm_dbg.h>
#include "uvmmh.h"
#include "memory.h"

                       
UINT32  heap_base;
UINT32  heap_current;
UINT32  heap_tops;

VOID
ZeroMem(
  VOID*   Address,
  UINT32  Size
  )
{
  UINT8* Source;

  Source = (UINT8*)Address;
  while (Size--)
  {
    *Source++ = 0;
  }
}

/*
  AllocateMemory():
    Simple memory allocation routine
*/
VOID*
AllocateMemory(
  UINT32 size_request
  )
{
  UINT32 Address;

  if (heap_current + size_request > heap_tops)
  {
      VMM_LOG(mask_uvmm, level_error, "Allocation request exceeds heap's size\r\n");
      VMM_LOG(mask_uvmm, level_error, "Heap current = 0x", heap_current);
      VMM_LOG(mask_uvmm, level_error, "Requested size =0x", size_request);
      VMM_LOG(mask_uvmm, level_error, "Heap tops = 0x", heap_tops);

    return NULL;
  }
  Address = heap_current;
  heap_current+=size_request;
  ZeroMem((VOID*)Address, size_request);
  return (VOID*)Address;
}

/*
  PrintE820BiosMemoryMap():
    Routine to print the E820 BIOS memory map
*/
VOID
PrintE820BiosMemoryMap(
  //INT15_E820_MEMORY_MAP *BiosMemoryMap
  )
{
#if 0
  UINT32                        NumberOfMemoryEntries;
  UINT32                        Index;

  NumberOfMemoryEntries = BiosMemoryMap->MemoryMapSize / sizeof(INT15_E820_MEMORY_MAP_ENTRY);
  PRINT_STRING_AND_VALUE("NumberOfMemoryEntries = 0x", NumberOfMemoryEntries);

  for (Index = 0 ; Index < NumberOfMemoryEntries ; Index++)
  {
    PRINT_STRING("BaseAddress = 0x");
    PRINT_VALUE((UINT32)BiosMemoryMap->MemoryMapEntry[Index].BaseAddress);
    PRINT_STRING(" Length = 0x");
    PRINT_VALUE((UINT32)BiosMemoryMap->MemoryMapEntry[Index].Length);
    PRINT_STRING(" Type = 0x");
    PRINT_VALUE(BiosMemoryMap->MemoryMapEntry[Index].AddressRangeType);
    PRINT_STRING("\n");
  }
#endif
}

VOID
InitializeMemoryManager(
    UINT64 *    HeapBaseAddress,
    UINT64 *    HeapBytes
  )
{
  heap_current = heap_base = *(UINT32*)HeapBaseAddress;
  heap_tops = heap_base + *(UINT32*)HeapBytes;
}

VOID
CopyMem(
  VOID *Dest,
  VOID *Source,
  UINT32 Size
  )
{
  UINT8 *d = (UINT8*)Dest;
  UINT8 *s = (UINT8*)Source;

  while (Size--)
  {
    *d++ = *s++;
  }
}

BOOLEAN
CompareMem(
  VOID *Source1,
  VOID *Source2,
  UINT32 Size
  )
{
  UINT8 *s1 = (UINT8*)Source1;
  UINT8 *s2 = (UINT8*)Source2;

  while (Size--)
  {
    if (*s1++ != *s2++)
    {
      VMM_LOG(mask_uvmm, level_error, "Compare mem failed\n");
      return FALSE;
    }
  }
  return TRUE;
}

#define PAGE_SIZE (1024 * 4)

void * evmm_page_alloc(UINT32 pages)
{
	UINT32 address;
	UINT32 size = pages * PAGE_SIZE;

	address = ALIGN_FORWARD(heap_current, PAGE_SIZE);
	heap_current = address + size;
	ZeroMem((void*)address, size);
	return (void*)address;
}

