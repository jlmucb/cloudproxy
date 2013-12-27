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

/*

    Implements both PE32 and PE32+ image parsing

*/

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(PARSE_PE_IMAGE_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(PARSE_PE_IMAGE_C, __condition)
#include "parse_pe_image.h"
#include "pe_def.h"
#include "lock.h"
#include "heap.h"

#pragma warning (disable : 4100)

typedef struct _SECTION_TABLE_INFO {
    IMAGE_SECTION_HEADER* section_table;
    UINT32                number_of_sections;
    UINT8                 pad[4];
} SECTION_TABLE_INFO;

static EXEC_IMAGE_SECTION_INFO* g_section_info_arr = NULL;
static UINT32                   g_section_info_size = 0; // in entries
static VMM_LOCK                 g_section_lock;
static BOOLEAN                  g_is_locked;

//------------------------ Internal -----------------------------------
static
void fill_sections_info( const char* image_base_address,
                         SECTION_TABLE_INFO info )
{
    IMAGE_SECTION_HEADER*    p_section_header = 0;
    UINT32                   section_index;
    EXEC_IMAGE_SECTION_INFO* p_info = 0;


    // 2. now copy the sections
    for (section_index = 0; section_index < info.number_of_sections; ++section_index)
    {
        p_section_header = &(info.section_table[section_index]);

        if (!p_section_header->VirtualAddress ||
            !p_section_header->Misc.VirtualSize)
        {
            // empty section
            continue;
        }

        p_info           = g_section_info_arr + g_section_info_size;
        ++g_section_info_size;

        p_info->name  = (const char*)p_section_header->Name;
        p_info->start = (char*)image_base_address + p_section_header->VirtualAddress;
        p_info->size  = p_section_header->Misc.VirtualSize;
        p_info->readable =
                (BITMAP_GET( p_section_header->Characteristics, IMAGE_SCN_MEM_READ ) != 0);
        p_info->writable =
                (BITMAP_GET( p_section_header->Characteristics, IMAGE_SCN_MEM_WRITE) != 0);
        p_info->executable =
                (BITMAP_GET( p_section_header->Characteristics, IMAGE_SCN_MEM_EXECUTE) != 0);

    }

}

static
SECTION_TABLE_INFO find_section_table(
                    const void* image,
                    UINT32      image_size )
{
    IMAGE_DOS_HEADER*   p_dos_header = (IMAGE_DOS_HEADER*)image;
    UINT32              nt_header_offset = 0;
    IMAGE_NT_HEADERS32* p_nt_header_32 = 0; // both PE32 and PE32+ image have
                                            // same first 2 fields in IMAGE_NT_HEADERS
    SECTION_TABLE_INFO  info;

    VMM_ASSERT( image && image_size );
    VMM_ASSERT( p_dos_header->e_magic == IMAGE_DOS_SIGNATURE );

    nt_header_offset = p_dos_header->e_lfanew;

    p_nt_header_32 = (IMAGE_NT_HEADERS32*)
                ((char*)p_dos_header + nt_header_offset);

    // both PE32 and PE32+ have the same first 2 fields in the
    // IMAGE_NT_HEADERS32 structure: Signature and FileHeader
    VMM_ASSERT( p_nt_header_32->Signature == IMAGE_NT_SIGNATURE );

    // pointer to the first section header does not depend on the arch/format
    // section table starts immediately after OptionalHeader
    info.section_table = (IMAGE_SECTION_HEADER*)
        ((char*)p_nt_header_32 +
            OFFSET_OF(IMAGE_NT_HEADERS32, OptionalHeader ) +
            p_nt_header_32->FileHeader.SizeOfOptionalHeader);

    info.number_of_sections = p_nt_header_32->FileHeader.NumberOfSections;

    return info;
}

static
void build_section_info_arr( const void* image, UINT32 image_size )
{
    SECTION_TABLE_INFO info;

    VMM_ASSERT( image );
    VMM_ASSERT( image_size );

    info = find_section_table( image, image_size );

    VMM_ASSERT( info.section_table && info.number_of_sections );

    g_section_info_arr = (EXEC_IMAGE_SECTION_INFO*)
        vmm_memory_alloc( sizeof(EXEC_IMAGE_SECTION_INFO)* info.number_of_sections );

    VMM_ASSERT( g_section_info_arr );

    fill_sections_info( image, info );

    VMM_ASSERT( g_section_info_size );
}

static
void destroy_section_info_arr( void )
{
    VMM_ASSERT( g_section_info_arr );

    vmm_memory_free( g_section_info_arr );

    g_section_info_arr = NULL;
    g_section_info_size = 0;
}

//------------------------- Interface ----------------------------------

void exec_image_initialize( void )
{
    lock_initialize( &g_section_lock );
    g_section_info_arr = NULL;
    g_section_info_size = 0;
    g_is_locked = FALSE;
}

const EXEC_IMAGE_SECTION_INFO*
exec_image_section_first( const void* image, UINT32 image_size,
                          EXEC_IMAGE_SECTION_ITERATOR* ctx )
{
    EXEC_IMAGE_SECTION_INFO* info = NULL;

    lock_acquire( &g_section_lock );
    g_is_locked = TRUE;

    build_section_info_arr( image, image_size );

    info = ARRAY_ITERATOR_FIRST( EXEC_IMAGE_SECTION_INFO,
                                 g_section_info_arr,
                                 g_section_info_size,
                                 ctx );

    if (! info)
    {
        destroy_section_info_arr();
        g_is_locked = FALSE;
        lock_release( &g_section_lock );
    }

    return info;
}

const EXEC_IMAGE_SECTION_INFO*
exec_image_section_next( EXEC_IMAGE_SECTION_ITERATOR* ctx )
{
    EXEC_IMAGE_SECTION_INFO* info = NULL;

    VMM_ASSERT( g_is_locked == TRUE );

    info = ARRAY_ITERATOR_NEXT( EXEC_IMAGE_SECTION_INFO, ctx );

    if (! info)
    {
        destroy_section_info_arr();
        g_is_locked = FALSE;
        lock_release( &g_section_lock );
    }

    return info;
}

