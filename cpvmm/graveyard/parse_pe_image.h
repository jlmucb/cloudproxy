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

#ifndef _PARSE_PE_IMAGE_H_
#define _PARSE_PE_IMAGE_H_

#include "vmm_defs.h"
#include "array_iterators.h"


// Get info about the uVMM memory image itself
typedef struct _EXEC_IMAGE_SECTION_INFO {
    const char* name;
    const char* start;
    UINT32      size;
    BOOLEAN     readable;
    BOOLEAN     writable;
    BOOLEAN     executable;
} EXEC_IMAGE_SECTION_INFO;

typedef GENERIC_ARRAY_ITERATOR EXEC_IMAGE_SECTION_ITERATOR;


// Iterate through section info while EXEC_IMAGE_SECTION_INFO* != NULL
const EXEC_IMAGE_SECTION_INFO*
exec_image_section_first( const void* image, UINT32 image_size,
                          EXEC_IMAGE_SECTION_ITERATOR* ctx );

const EXEC_IMAGE_SECTION_INFO*
exec_image_section_next( EXEC_IMAGE_SECTION_ITERATOR* ctx );

// initialize
void exec_image_initialize( void );

#endif // _PARSE_PE_IMAGE_H_
