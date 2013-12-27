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

#ifdef WIN32
#    include <memory.h>
#    include <malloc.h>
#    include <stdio.h>
#else
#   include "vmm_defs.h"
#endif

#include "image_access_file.h"


/*--------------------------Local Types Definitions-------------------------*/
struct _MEM_CHUNK {
    struct _MEM_CHUNK *next;    // used for purge only
    long    offset;
    long    length;
    char    buffer[1];
};

struct _FILE_IMAGE_ACCESS_S {
    GEN_IMAGE_ACCESS_S  gen;            // inherits to GEN_IMAGE_ACCESS_S
    FILE               *file;
    struct _MEM_CHUNK  *memory_list;    // should be free when image access destructed
};

typedef struct _FILE_IMAGE_ACCESS_S FILE_IMAGE_ACCESS_S;

/*-------------------------Local Functions Declarations-----------------------*/
static void   file_image_close(GEN_IMAGE_ACCESS_S *);
static size_t file_image_read(GEN_IMAGE_ACCESS_S *, void *, size_t, size_t);
static size_t file_image_map_to_mem(GEN_IMAGE_ACCESS_S *, void **, size_t, size_t);


/*---------------------------------------Code---------------------------------*/

GEN_IMAGE_ACCESS_S * file_image_create(
    char *filename)
{
    FILE_IMAGE_ACCESS_S *fia;
    FILE *file;

    file = fopen(filename, "rb");
    if (NULL == file)
    {
        return NULL;
    }

    fia = malloc(sizeof(FILE_IMAGE_ACCESS_S));
    if (NULL == file)
    {
        return NULL;
    }

    fia->gen.close      = file_image_close;
    fia->gen.read       = file_image_read;
    fia->gen.map_to_mem = file_image_map_to_mem;
    fia->file           = file;
    fia->memory_list    = NULL;
    return &fia->gen;
}

void file_image_close(
    GEN_IMAGE_ACCESS_S *ia)
{
    FILE_IMAGE_ACCESS_S *fia = (FILE_IMAGE_ACCESS_S *) ia;
    struct _MEM_CHUNK   *chunk;

    fclose(fia->file);

    while (NULL != fia->memory_list)
    {
        chunk = fia->memory_list;
        fia->memory_list = fia->memory_list->next;
        free(chunk);
    }
    free(fia);
}

size_t file_image_read(
    GEN_IMAGE_ACCESS_S  *ia,
    void                *dest,
    size_t              src_offset,
    size_t              bytes)
{
    FILE_IMAGE_ACCESS_S *fia = (FILE_IMAGE_ACCESS_S *) ia;

    if (0 != fseek(fia->file, src_offset, SEEK_SET))
    {
        return 0;
    }
    return fread(dest, 1, bytes, fia->file);
}

size_t file_image_map_to_mem(
    GEN_IMAGE_ACCESS_S  *ia,
    void                **dest,
    size_t              src_offset,
    size_t              bytes)
{
    FILE_IMAGE_ACCESS_S *fia = (FILE_IMAGE_ACCESS_S *) ia;
    struct _MEM_CHUNK    *chunk;
    size_t                bytes_mapped;

    // first search if this chunk is already allocated
    for (chunk = fia->memory_list; chunk != NULL; chunk = chunk->next)
    {
        if (chunk->offset == src_offset && chunk->length == bytes)
        {
            break;    // found
        }
    }

    if (NULL == chunk)
    {
        // if not found, allocate new chunk
        size_t bytes_to_alloc = sizeof(struct _MEM_CHUNK) - sizeof(chunk->buffer) + bytes;
        chunk = (struct _MEM_CHUNK *) malloc(bytes_to_alloc);
        chunk->next = fia->memory_list;
        fia->memory_list = chunk;
        chunk->offset = src_offset;
        chunk->length = bytes;
        bytes_mapped = file_image_read(ia, chunk->buffer, src_offset, bytes);
    }
    else
    {
        // reuse old chunk
        bytes_mapped = bytes;
    }

    *dest = chunk->buffer;

    return bytes_mapped;
}

