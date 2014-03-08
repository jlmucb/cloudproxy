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

#pragma once


// The following definitions and macros will be used to perform alignment
#define UVMM_PAGE_TABLE_SHIFT    12
#define UVMM_PAGE_4KB_SIZE       (1 << UVMM_PAGE_TABLE_SHIFT)
#define UVMM_PAGE_4KB_MASK       (UVMM_PAGE_4KB_SIZE - 1)
#define UVMM_PAGE_ALIGN_4K(x)    ((((x) & ~UVMM_PAGE_4KB_MASK)==(x)) ? (x) : ((x) & ~UVMM_PAGE_4KB_MASK) + UVMM_PAGE_4KB_SIZE)

#define UNEXPECTED_ERROR        -1



//  MEMORY_PTR
//
//  Dummy tyoedef: supports for easy change of memory addressing in 
//  IMAGE_MEM_INFO_STRUC struct.
typedef ADDRESS  MEMORY_PTR;


//  struct _IMAGE_MEM_INFO_STRUC
//
//  This struct contains information about the images loaded by loader
//  for use by the uVMM
typedef struct _IMAGE_MEM_INFO_STRUC
{
    MEMORY_PTR  p_image_base_address;   //  image address (loaded by loader)
    UINT32      image_byte_size;        //  size of image
} IMAGE_MEM_INFO_STRUC, *PIMAGE_MEM_INFO_STRUC;


//  defines, for accessing the IMAGE_MEM_INFO_STRUC structure
#define image_index_uvmm_lp         0
#define image_index_uvmm_h          1 
#define image_index_uvmm_load_thunk 2 
#define image_index_uvmm_exe        3
#define image_index_bios_e820       4
#define image_index_uvmm_env        5
#define image_index_cos_env         6
#define image_index_sos1_env        7

//  struct _MEMORY_INFO
//
//  This struct contains all the information that uVMM-LP requires for 
//  its own operation, or is required to hand over to uVMM-H
//
typedef struct _E820_LOADER_INFO
{
    PINT15_E820_MEMORY_MAP_ENTRY_EXT    p_e820_data;        // pointer to E820 data
    UINT32                              e820_entries;       // entries count
    UINT32                              e820_entry_size;    // size as indicated by BIOS
    UINT32                              e820_buffer_size;   // limit of region - do not cross!
}E820_LOADER_INFO, *PE820_LOADER_INFO;

typedef struct _LOADER_PARAMS
{
    E820_LOADER_INFO        e820_info;          // e820 info from loader
    PIMAGE_MEM_INFO_STRUC   p_loaded_images;    // array of images loaded by loader
    UINT32                  loaded_images_count;// # of images
    UINT32                  uvmm_footprint;     // uVMM footprint size (MB)
} LOADER_PARAMS, *PLOADER_PARAMS;


typedef VOID (*uvmmh_entry) (
    PLOADER_PARAMS    p_loader_params
    ) ;


