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

#include "vmm_defs.h"
#include "hw_utils.h"

//*****************************************************************************
//
// Implement utilities for BITARRAY
//
//*****************************************************************************

#if 8 == ARCH_ADDRESS_WIDTH
    #define SCAN_TYPE UINT64
    #define SCAN_FUNC hw_scan_bit_forward64
#else
    #define SCAN_TYPE UINT32
    #define SCAN_FUNC hw_scan_bit_forward
#endif

void bitarray_enumerate_bits( UINT8* bitarray, UINT32 bitarray_size_in_bits,
                              BITARRAY_ENUM_FUNC cb, void* cb_data )
{
    UINT32  base_field_id = 0;
    UINT32  idx;
    UINT32  bit_idx;
    UINT32  bytes_to_copy;
    UINT32  extra_bytes;

    union {
        SCAN_TYPE uint;
        UINT8     uint8[sizeof(SCAN_TYPE)];
    } temp_mask;

    // something was changed. need to copy it to the hw data base
    base_field_id = 0;

    while (base_field_id < bitarray_size_in_bits)
    {
        // fill what to search. Bit numbers in our case raise from MSB to LSB.
        bytes_to_copy = sizeof(SCAN_TYPE);
        extra_bytes   = (bitarray_size_in_bits - base_field_id + 7) / 8;
        if (extra_bytes < bytes_to_copy)
        {
            bytes_to_copy = extra_bytes;
        }

        temp_mask.uint = 0;
        for (idx = 0; idx < bytes_to_copy; ++idx)
        {
            temp_mask.uint8[idx] = bitarray[ BITARRAY_BYTE( base_field_id + idx*8 ) ];
        }

        while (temp_mask.uint != 0)
        {
            SCAN_FUNC( &bit_idx, temp_mask.uint );

            BITARRAY_CLR( temp_mask.uint8, bit_idx);

            cb( base_field_id + bit_idx, cb_data);
        }

        base_field_id += sizeof(SCAN_TYPE) * 8;
    }
}


