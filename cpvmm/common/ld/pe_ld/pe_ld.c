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

/*
    Implements both PE32 and PE32+ image loading inlcuding base relocations
    This is a specially crafted code to create
    position-independent code and data to be used from protected mode assembler
    DO NOT USE GLOBALS and STATICS!!!!!
 */

#ifdef POST_OS_LAUNCH
#include <ntddk.h>
#define PHYSICAL_ADDRESS(address) MmGetPhysicalAddress(address).QuadPart

#undef UNIT_TESTING
#define vmm_memset memset
#define vmm_memcpy memcpy

#else
#define PHYSICAL_ADDRESS(address) ((UINT32)address)
#endif

#include "pe_loader.h"
#include "pe_def.h"

#ifdef UNIT_TESTING
    #include <memory.h>
    #include <stdio.h>
    #include <stdlib.h>

    #define PE_ASSERT( cond, message ) if (!(cond)) { printf("Assertion %s failed: %s (%s:%d)\n", #cond, #message, __FILE__, __LINE__); exit(1); }
    #define PE_TESTING( code ) code

    #define vmm_memset memset
    #define vmm_memcpy memcpy
#else
    #define PE_ASSERT( cond, message ) if (!(cond)) for(;;);
    #define PE_TESTING( code )

#endif

#ifndef POST_OS_LAUNCH
// forward declarations
// do not inlcude libc implementation in C because this will break assembler compatibility
void *  __cdecl vmm_memset(void *dest, int filler, size_t count);
void *  __cdecl vmm_memcpy(void *dest, const void* src, size_t count);
#endif

//
// Emulated 64 bit integer. Needed to avoid 64-bit arithmetic on 32bit machine
//
typedef union _UINT64_EMULATED {
    UINT64  uint64;
    struct {
        UINT32  low32;
        UINT32  high32;
    }       fields32;
} UINT64_EMULATED;

typedef enum _PE_IMAGE_TYPE {
    PE_IMAGE_UNKNOWN = 0,
    PE_IMAGE32,
    PE_IMAGE64
} PE_IMAGE_TYPE;


// Maximum DOS header size is less then 8K
#define MAX_DOS_HEADER_SIZE  (8 KILOBYTES)


static BOOLEAN perform_base_relocations( PE_IMAGE_TYPE image_type,
                        IMAGE_NT_HEADERS32* p_nt_header_32, char* image_base_address )
{
    IMAGE_BASE_RELOCATION*  base_relocs_block = 0;
    IMAGE_BASE_RELOCATION*  base_relocs_block_limit = 0;
    IMAGE_BASE_RELOCATION*  current_base_relocs_block = 0;
    IMAGE_DATA_DIRECTORY    base_relocs_data_entry;
    IMAGE_NT_HEADERS64*     p_nt_header_64 = (IMAGE_NT_HEADERS64*)p_nt_header_32;
    UINT64_EMULATED         preferred_load_addr = {0};
    UINT32                  reloc_index;
    UINT32                  number_of_relocs_in_group;
    char*                   curr_page;
    WORD*                   reloc_group_arr;
    INT64                   base_shift; // to be added to relocated data

    if (image_type == PE_IMAGE32) {
        preferred_load_addr.fields32.low32 = p_nt_header_32->OptionalHeader.ImageBase;
        base_relocs_data_entry = p_nt_header_32->
                OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }
    else {
        preferred_load_addr.uint64 = p_nt_header_64->OptionalHeader.ImageBase;

        base_relocs_data_entry = p_nt_header_64->
                OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }
    // may be loaded address is the same as preferred ?
    // assume - we load only lower than 4G
    if ((preferred_load_addr.fields32.high32 == 0) && (preferred_load_addr.fields32.low32 == 
            (UINT32) (PHYSICAL_ADDRESS(image_base_address)))) {
        // we are done
        return TRUE;
    }

    if (!base_relocs_data_entry.VirtualAddress || !base_relocs_data_entry.Size) {
        // image is position-independent (PIC)
        return TRUE;
    }

    // assumes that image_base_address < 4G in order to avoid sign extension of
    // image_base_address
    base_shift = (INT64) PHYSICAL_ADDRESS(image_base_address) - preferred_load_addr.uint64;

    PE_TESTING( printf("Base shift from 0x%I64x to 0x%x is 0x%I64x\n", preferred_load_addr.uint64, image_base_address, base_shift) );

    base_relocs_block = (IMAGE_BASE_RELOCATION*)
        (image_base_address + base_relocs_data_entry.VirtualAddress);

    base_relocs_block_limit = (IMAGE_BASE_RELOCATION*)
        ((char*)base_relocs_block + base_relocs_data_entry.Size);

    // base relocations are groupped in blocks.
    // each block has a block header that contains page RVA, size of block
    // including the header itself + array of WORD structs with offside inside the
    // page and relocation type
    while (base_relocs_block != base_relocs_block_limit) {
        current_base_relocs_block = base_relocs_block;
        base_relocs_block = (IMAGE_BASE_RELOCATION*)
            ((char*)base_relocs_block + current_base_relocs_block->SizeOfBlock);

        curr_page = image_base_address + current_base_relocs_block->VirtualAddress;

        number_of_relocs_in_group =
            (current_base_relocs_block->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION)/sizeof(WORD);

        reloc_group_arr = (WORD*)((char*)current_base_relocs_block+IMAGE_SIZEOF_BASE_RELOCATION);

        for (reloc_index = 0; reloc_index < number_of_relocs_in_group; ++reloc_index) {
            WORD reloc = reloc_group_arr[reloc_index];
            UINT32 reloc_type = IMAGE_REL_BASED_TYPE(reloc);
            UINT32 reloc_offset = IMAGE_REL_BASED_OFFSET(reloc);

            if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
                // padding
                PE_TESTING(printf("Skip padding\n"));
                continue;
            }
            else if (reloc_type == IMAGE_REL_BASED_HIGHLOW) {
                // 32bit relocation
                PE_TESTING(printf("Updating 32 bit value at 0x%x from 0x%x to 0x%x\n",
                                  curr_page + reloc_offset, *((INT32*)(curr_page + reloc_offset)),
                                  *((INT32*)(curr_page + reloc_offset)) + (INT32)base_shift ));

                *((INT32*)(curr_page + reloc_offset)) += (INT32)base_shift;
            }
            else if (reloc_type == IMAGE_REL_BASED_DIR64) {
                // 64bit relocation
                PE_TESTING(printf("Updating 64 bit value at 0x%x from 0x%I64x to 0x%I64x\n",
                                curr_page + reloc_offset, *((INT64*)(curr_page + reloc_offset)),
                                *((INT64*)(curr_page + reloc_offset)) + (INT64)base_shift ));
                *((INT64*)(curr_page + reloc_offset)) += (INT64)base_shift;
            }
            else {
                // any other allocation type is not supported
                return FALSE;
            }
        }
    }
    return TRUE;

}

static void copy_image_sections( const char* file_mapped_into_memory,
                IMAGE_SECTION_HEADER* section_table, UINT32 number_of_sections,
                char* image_base_address, UINT32 allocated_size )
{
    IMAGE_SECTION_HEADER*   p_section_header = 0;
    UINT32                  section_index;
    char*                   loaded_buffer = 0;
    char*                   raw_data      = 0;
    UINT32                  amount_to_copy;

    // 1. first of all copy all image headers upto the first section
    PE_ASSERT( section_table[0].PointerToRawData < allocated_size,
               Allocated size for image loading is too small even for image headers );
    PE_TESTING(printf("Copying image headers from 0x%x to 0x%x. Size 0x%x\n",
                        file_mapped_into_memory,
                        image_base_address,
                        section_table[0].PointerToRawData ));
    vmm_memcpy( image_base_address, file_mapped_into_memory, section_table[0].PointerToRawData );

    // 2. now copy the sections
    for (section_index = 0; section_index < number_of_sections; ++section_index) {
        p_section_header = &(section_table[section_index]);
        if (!p_section_header->VirtualAddress || !p_section_header->Misc.VirtualSize) {
            // empty section
            continue;
        }
        PE_ASSERT( (p_section_header->VirtualAddress +
                    p_section_header->Misc.VirtualSize) < allocated_size,
                   Allocated size for image loading is too small );
        loaded_buffer = (char*)image_base_address + p_section_header->VirtualAddress;
        if (p_section_header->PointerToRawData) {
            // raw data exists. Copy it.
            raw_data = (char*)file_mapped_into_memory + p_section_header->PointerToRawData;

            // data in file may be larger than memory size because of file alignment
            // copy the min between two
            p_section_header->SizeOfRawData : p_section_header->Misc.VirtualSize;
            PE_TESTING(printf("Copying raw data for section %s 0x%x to 0x%x. Size 0x%x\n",
                                p_section_header->Name, raw_data, loaded_buffer, amount_to_copy ));
            // copy the raw data
           // KdPrint(("loaded_buffer= 0x%I64x, and amount_to_copy= 0x%I64x\n",loaded_buffer,amount_to_copy));
            vmm_memcpy( loaded_buffer, raw_data, amount_to_copy );
        }
        // now zero the unintialized section part
        if (p_section_header->SizeOfRawData < p_section_header->Misc.VirtualSize) {
            PE_TESTING(printf("Zeroing uninit data for section %s 0x%x. Size 0x%x\n",
                          p_section_header->Name, loaded_buffer + p_section_header->SizeOfRawData,
                          p_section_header->Misc.VirtualSize - p_section_header->SizeOfRawData ));
            vmm_memset( loaded_buffer + p_section_header->SizeOfRawData, 0,
                        p_section_header->Misc.VirtualSize - p_section_header->SizeOfRawData );
        }
    }
}


// Get info required for image loading
// Input:
//  void* file_mapped_into_memory - file directly read or mapped in RAM
// Output:
//  PE_IMAGE_INFO - fills the structure
//
//  Return value - GET_PE_IMAGE_INFO_STATUS

GET_PE_IMAGE_INFO_STATUS get_PE_image_info( const void* file_mapped_into_memory,
                PE_IMAGE_INFO*  p_image_info)
{
    IMAGE_DOS_HEADER*   p_dos_header = (IMAGE_DOS_HEADER*)file_mapped_into_memory;
    UINT32              nt_header_offset = 0;
    IMAGE_NT_HEADERS32* p_nt_header_32 = 0; // both PE32 and PE32+ image have
                                          // same first 2 fields in IMAGE_NT_HEADERS
    IMAGE_DATA_DIRECTORY import_table_data_entry;
    PE_IMAGE_TYPE       image_type = PE_IMAGE_UNKNOWN;
    WORD                machine;
    WORD                magic;

    if (p_image_info) {
        p_image_info->machine_type = PE_IMAGE_MACHINE_UNKNOWN;
        p_image_info->load_size    = 0;
    }
    if ((p_dos_header == 0) || (p_image_info == 0)) {
        // wrong parameters
        return GET_PE_IMAGE_INFO_WRONG_PARAMS;
    }

    // check that image is really PE32/PE32+ image.
    // PE image starts from DOS header
    if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        // not a DOS image derivative
        return GET_PE_IMAGE_INFO_WRONG_FORMAT;
    }
    nt_header_offset = p_dos_header->e_lfanew;
    if (nt_header_offset > MAX_DOS_HEADER_SIZE) {
        // wrong DOS header
        return GET_PE_IMAGE_INFO_WRONG_FORMAT;
    }
    p_nt_header_32 = (IMAGE_NT_HEADERS32*)
                ((char*)p_dos_header + nt_header_offset);
    // both PE32 and PE32+ have the same first 2 fields in the
    // IMAGE_NT_HEADERS32 structure: Signature and FileHeader
    if (p_nt_header_32->Signature != IMAGE_NT_SIGNATURE) {
        // not a NT image
        return GET_PE_IMAGE_INFO_WRONG_FORMAT;
    }
    // check machine type
    machine = p_nt_header_32->FileHeader.Machine;
    if (machine == IMAGE_FILE_MACHINE_I386) {
        p_image_info->machine_type = PE_IMAGE_MACHINE_X86;
    }
    else if (machine == IMAGE_FILE_MACHINE_AMD64) {
        p_image_info->machine_type = PE_IMAGE_MACHINE_EM64T;
    }
    else {
        // unsupported machine
        return GET_PE_IMAGE_INFO_WRONG_MACHINE;
    }
    // check format type
    magic = p_nt_header_32->OptionalHeader.Magic;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        image_type = PE_IMAGE32;
        p_image_info->load_size = p_nt_header_32->OptionalHeader.SizeOfImage;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        image_type = PE_IMAGE64;
        p_image_info->load_size =
            ((IMAGE_NT_HEADERS64*)p_nt_header_32)->OptionalHeader.SizeOfImage;
    }
    else {
        // unsupported format
        return GET_PE_IMAGE_INFO_WRONG_FORMAT;
    }

    // check for consistency:
    //    EM64T should use PE32+ only,
    //    x86   should use PE32 only
    if (!( ((image_type == PE_IMAGE32) && (p_image_info->machine_type == PE_IMAGE_MACHINE_X86)) ||
         ((image_type == PE_IMAGE64) && (p_image_info->machine_type == PE_IMAGE_MACHINE_EM64T)))) {
        return GET_PE_IMAGE_INFO_WRONG_FORMAT;
    }

    // check that image is relocatable.
    // relocatable means not signed as IMAGE_FILE_RELOCS_STRIPPED
    if (p_nt_header_32->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        return GET_PE_IMAGE_INFO_NOT_RELOCATABLE;
    }
    // check that all symbols are resolved.
    // For PE32/PE32+ format this means that no IMPORT section exist
    if (image_type == PE_IMAGE32) {
        import_table_data_entry = p_nt_header_32->
                OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    else {
        import_table_data_entry = ((IMAGE_NT_HEADERS64*)p_nt_header_32)->
                OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    if ((import_table_data_entry.Size != 0) || (import_table_data_entry.VirtualAddress != 0)) {
        return GET_PE_IMAGE_INFO_UNRESOLVED_SYMBOLS;
    }
    return GET_PE_IMAGE_INFO_OK;
}


// load PE image into memory
// Input:
//  void* file_mapped_into_memory - file directly read or mapped in RAM
//  void* image_base_address      - load image to this address. Must be alined
//                                  on 4K.
//  UINT32 allocated_size         - buffer size for image
//  UINT64* p_entry_point_address - address of the UINT64 that will be filled
// Output:
//  Return value - FALSE on any error
BOOLEAN load_PE_image( const void*  file_mapped_into_memory, void* image_base_address,
                       UINT32 allocated_size, UINT64* p_entry_point_address)
{
    PE_IMAGE_INFO           image_info;
    PE_IMAGE_TYPE           image_type = PE_IMAGE_UNKNOWN;
    IMAGE_NT_HEADERS32*     p_nt_header_32 = 0;
    IMAGE_SECTION_HEADER*   section_table = 0;

    if (! (file_mapped_into_memory && image_base_address && allocated_size && p_entry_point_address)) {
        // wrong params
        return FALSE;
    }
    // image base have to be 4K aligned
    if (((size_t)image_base_address & PAGE_4KB_MASK) != 0) {
        // image address not aligned
        return FALSE;
    }
    if (get_PE_image_info( file_mapped_into_memory, &image_info) != GET_PE_IMAGE_INFO_OK) {
        // wrong image
        return FALSE;
    }
    if (allocated_size < image_info.load_size) {
        // too small buffer allocated
        return FALSE;
    }

    // get_PE_image_info() already checked for consistency
    image_type = (image_info.machine_type == PE_IMAGE_MACHINE_X86) ?  PE_IMAGE32 : PE_IMAGE64;
    p_nt_header_32 = (IMAGE_NT_HEADERS32*)
         ((char*)file_mapped_into_memory + ((IMAGE_DOS_HEADER*)file_mapped_into_memory)->e_lfanew);
    // pointer to the first section header does not depend on the arch/format
    // section table starts immediately after OptionalHeader
    section_table = (IMAGE_SECTION_HEADER*)
        ((char*)p_nt_header_32 + OFFSET_OF(IMAGE_NT_HEADERS32, OptionalHeader ) +
            p_nt_header_32->FileHeader.SizeOfOptionalHeader);

    // 1. Copy image sections
    copy_image_sections( (char*)file_mapped_into_memory, section_table,
                         p_nt_header_32->FileHeader.NumberOfSections, (char*)image_base_address,
                         allocated_size );

    // 2. now perform base relocation
    if (! perform_base_relocations( image_type, p_nt_header_32, (char*)image_base_address )) {
        return FALSE;
    }
    if (image_type == PE_IMAGE32) {
        *p_entry_point_address = (UINT64) ((char*)image_base_address +
                p_nt_header_32->OptionalHeader.AddressOfEntryPoint);
    }
    else {
        *p_entry_point_address = (UINT64) ((char*)image_base_address +
               ((IMAGE_NT_HEADERS64*)p_nt_header_32)->OptionalHeader.AddressOfEntryPoint);
    }
    return TRUE;
}

