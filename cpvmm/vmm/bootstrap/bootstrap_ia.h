/*
 * File: bootstrap_ia.h
 * Description: intel architecture definitions
 * Author: John Manferdelli 
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


#ifndef _BOOTSTRAP_IA_H_
#define _BOOTSTRAP_IA_H_

#include "bootstrap_types.h"

// IA-32 Interrupt Descriptor Table - Gate Descriptor 
typedef struct {
    uint32_t  OffsetLow:16;   // Offset bits 15..0 
    uint32_t  Selector:16;    // Selector 
    uint32_t  Reserved_0:8;   // Reserved
    uint32_t  GateType:8;     // Gate Type.  See #defines above
    uint32_t  OffsetHigh:16;  // Offset bits 31..16
} IA32_IDT_GATE_DESCRIPTOR;


// Descriptor for the Global Descriptor Table(GDT) and Interrupt Descriptor Table(IDT)
typedef struct {
    uint16_t  Limit;
    uint32_t  Base;
} IA32_DESCRIPTOR;


#endif
