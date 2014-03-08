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

#ifndef _PE_LOADER_H_
#define _PE_LOADER_H_

#include "vmm_defs.h"

typedef enum _PE_IMAGE_MACHINE_TYPE {
    PE_IMAGE_MACHINE_UNKNOWN = 0,
    PE_IMAGE_MACHINE_X86,
    PE_IMAGE_MACHINE_EM64T,
    ELF_IMAGE_MACHINE_X86 = 3,
    ELF_IMAGE_MACHINE_EM64T = 62
} PE_IMAGE_MACHINE_TYPE;

typedef enum _GET_PE_IMAGE_INFO_STATUS {
    GET_PE_IMAGE_INFO_OK = 0,
    GET_PE_IMAGE_INFO_WRONG_PARAMS,
    GET_PE_IMAGE_INFO_WRONG_FORMAT,
    GET_PE_IMAGE_INFO_WRONG_MACHINE,
    GET_PE_IMAGE_INFO_NOT_RELOCATABLE,
    GET_PE_IMAGE_INFO_UNRESOLVED_SYMBOLS
} GET_PE_IMAGE_INFO_STATUS;

typedef struct _PE_IMAGE_INFO {
    PE_IMAGE_MACHINE_TYPE   machine_type;
    UINT32                  load_size; // size as required for loading
} PE_IMAGE_INFO;


//----------------------------------------------------------------------
//
// Get info required for image loading
//
// Input:
//  void* file_mapped_into_memory - file directly read or mapped in RAM
//
// Output:
//  PE_IMAGE_INFO - fills the structure
//
//  Return value - GET_PE_IMAGE_INFO_STATUS
//----------------------------------------------------------------------
GET_PE_IMAGE_INFO_STATUS
get_PE_image_info(
    const void*     file_mapped_into_memory,
    PE_IMAGE_INFO*  p_image_info
    );

//----------------------------------------------------------------------
//
// load PE image into memory
//
// Input:
//  void* file_mapped_into_memory - file directly read or mapped in RAM
//  void* image_base_address      - load image to this address. Must be alined
//                                  on 4K.
//  UINT32 allocated_size         - buffer size for image
//  UINT64* p_entry_point_address - address of the UINT64 that will be filled
//                                  with the address of image entry point if
//                                  all is ok
//
// Output:
//  Return value - FALSE on any error
//----------------------------------------------------------------------
BOOLEAN
load_PE_image(
    const void*  file_mapped_into_memory,
    void*        image_base_address,
    UINT32       allocated_size,
    UINT64*      p_entry_point_address
    );

#endif // _PE_LOADER_H_

