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

#ifndef VMM_PHYS_MEM_TYPES_H
#define VMM_PHYS_MEM_TYPES_H

typedef enum {
    VMM_PHYS_MEM_UNCACHABLE      = 0x0, // UC
    VMM_PHYS_MEM_WRITE_COMBINING = 0x1, // WC
    VMM_PHYS_MEM_WRITE_THROUGH   = 0x4, // WT
    VMM_PHYS_MEM_WRITE_PROTECTED = 0x5, // WP
    VMM_PHYS_MEM_WRITE_BACK      = 0x6, // WB
    VMM_PHYS_MEM_UNCACHED        = 0x7, // UC-
    VMM_PHYS_MEM_LAST_TYPE = VMM_PHYS_MEM_UNCACHED,
    VMM_PHYS_MEM_UNDEFINED =     (~0)
} VMM_PHYS_MEM_TYPE;

#endif
