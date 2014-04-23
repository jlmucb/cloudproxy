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

#include "image_access_mem.h"


struct _MEM_IMAGE_ACCESS_S {
    GEN_IMAGE_ACCESS_S  gen;    // inherits to GEN_IMAGE_ACCESS_S
    char               *image;  // image located in memory
    size_t             size;    // size of image in memory, counted in bytes
};

typedef struct _MEM_IMAGE_ACCESS_S MEM_IMAGE_ACCESS_S;


static void   mem_image_close(GEN_IMAGE_ACCESS_S *);
static size_t mem_image_read(GEN_IMAGE_ACCESS_S *, void *, size_t, size_t);
static size_t mem_image_map_to_mem(GEN_IMAGE_ACCESS_S *, void **, size_t, size_t);


GEN_IMAGE_ACCESS_S * mem_image_create( char *image, size_t  size)
{
    MEM_IMAGE_ACCESS_S *mia = MALLOC(sizeof(MEM_IMAGE_ACCESS_S));

    mia->gen.close      = mem_image_close;
    mia->gen.read       = mem_image_read;
    mia->gen.map_to_mem = mem_image_map_to_mem;
    mia->image          = image;
    mia->size           = size;
    return &mia->gen;
}

void mem_image_close(
    GEN_IMAGE_ACCESS_S *ia)
{
    MEM_IMAGE_ACCESS_S *mia = MALLOC(sizeof(MEM_IMAGE_ACCESS_S));

    // nothing to do
    // in case of unzip, the memory should be purged
    FREE(mia);
}

size_t mem_image_read( GEN_IMAGE_ACCESS_S *ia, void *dest, size_t src_offset,
                        size_t bytes_to_read)
{
    MEM_IMAGE_ACCESS_S *mia = (MEM_IMAGE_ACCESS_S *) ia;

    if ((src_offset + bytes_to_read) > mia->size) {
        bytes_to_read = mia->size - src_offset;    // read no more than size
    }
    memcpy(dest, mia->image + src_offset, bytes_to_read);
    return bytes_to_read;
}

size_t mem_image_map_to_mem( GEN_IMAGE_ACCESS_S *ia, void **dest, size_t src_offset,
                             size_t bytes_to_read)
{
    MEM_IMAGE_ACCESS_S *mia = (MEM_IMAGE_ACCESS_S *) ia;
    if ((src_offset + bytes_to_read) > mia->size) {
        bytes_to_read = mia->size - src_offset;    // read no more than size
    }
    *dest = mia->image + src_offset;
    return bytes_to_read;
}

