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

#include "hw_includes.h"
#include "address.h"


static ADDRESS max_virtual_address;
static ADDRESS virtual_address_copmplement;

static UINT8 physical_address_size;
static UINT8 virtual_address_size;

extern UINT32 pw_reserved_bits_high_mask;

void addr_setup_address_space(void)
{
    UINT32 value = hw_read_address_size();

    physical_address_size = (UINT8) (value & 0xFF);
    virtual_address_size = (UINT8) ((value >> 8) & 0xFF);
    max_virtual_address = ((ADDRESS) 1 << virtual_address_size) - 1;;
    virtual_address_copmplement = ~(max_virtual_address >> 1);;
    // bit mask to identify the reserved bits in paging structure high order address field
    pw_reserved_bits_high_mask = ~((1 << (physical_address_size - 32)) - 1);
}

UINT8 addr_get_physical_address_size(void)
{
    return physical_address_size;
}

#ifdef INCLUDE_UNUSED_CODE
UINT8 addr_get_virtual_address_size(void)
{
    return virtual_address_size;
}
#endif

ADDRESS addr_canonize_address(
        ADDRESS address)
{
    if (address & virtual_address_copmplement) {
        address |= virtual_address_copmplement;
    }
    return address;
}
BOOLEAN addr_is_canonical(ADDRESS address)
{
    return addr_canonize_address(address) == address;
}

BOOLEAN addr_physical_is_valid(ADDRESS address)
{
    ADDRESS phys_address_space = BIT_VALUE64((ADDRESS)(physical_address_size));
    return address < phys_address_space;
}
