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

#include <mtrrs_abstraction.h>
#include <hw_utils.h>
#include <common_libc.h>
#include "vmm_dbg.h"
#include "address.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(MTRRS_ABSTRACTION_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(MTRRS_ABSTRACTION_C, __condition)

#pragma warning( disable : 4214 )

#define MTRRS_ABS_NUM_OF_SUB_RANGES 8
#define MTRRS_ABS_NUM_OF_FIXED_RANGE_MTRRS 11
#define MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS 10
#define MTRRS_ABS_HIGH_ADDR_SHIFT 32
#define MTRRS_ABS_ADDR_BASE_SHIFT 12


typedef union IA32_MTRRCAP_REG_U {
    struct {
        UINT32
            vcnt :8,
            fix  :1,
            res0 :1,
            wc   :1,
            res1 :21;
        UINT32
            res2 :32;
    } bits;
    UINT64 value;
} IA32_MTRRCAP_REG;

typedef union IA32_MTRR_DEF_TYPE_REG_U {
    struct {
        UINT32
            type                 : 8,
            res0                 : 2,
            fixed_range_enable   : 1,
            enable               : 1,
            res1                 : 20;
        UINT32
            res2                 : 32;
    } bits;
    UINT64 value;
} IA32_MTRR_DEF_TYPE_REG;

typedef union IA32_FIXED_RANGE_MTRR_U {
    UINT8  type[MTRRS_ABS_NUM_OF_SUB_RANGES];
    UINT64 value;
} IA32_FIXED_RANGE_MTRR;

typedef union IA32_MTRR_PHYSBASE_REG_U {
    struct {
        UINT32
            type          : 8,
            res0          : 4,
            phys_base_low : 20;
        UINT32
            phys_base_high : 20,
            res1           : 12;
    } bits;
    UINT64 value;
} IA32_MTRR_PHYSBASE_REG;

typedef union IA32_MTRR_PHYSMASK_REG_U {
    struct {
        UINT32
            res0      : 11,
            valid     : 1,
            phys_mask_low : 20;
        UINT32
            phys_mask_high : 20,
            res1      : 12;
    } bits;
    UINT64 value;
} IA32_MTRR_PHYSMASK_REG;

typedef struct MTRRS_ABS_FIXED_RANGE_DESC_S {
    UINT32 start_addr;
    UINT32 end_addr;
} MTRRS_ABS_FIXED_RANGE_DESC;


/*---------------------------------------------------*/
typedef struct MTRRS_ABSTRACTION_CACHED_INFO_S {
    IA32_MTRRCAP_REG ia32_mtrrcap_reg;
    IA32_MTRR_DEF_TYPE_REG ia32_mtrr_def_type;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix64k_00000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix16k_80000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix16k_A0000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_C0000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_C8000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_D0000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_D8000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_E0000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_E8000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_F0000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix4k_F8000;
    IA32_FIXED_RANGE_MTRR  ia32_mtrr_fix[MTRRS_ABS_NUM_OF_FIXED_RANGE_MTRRS];
    MTRRS_ABS_FIXED_RANGE_DESC ia32_mtrr_fix_range[MTRRS_ABS_NUM_OF_FIXED_RANGE_MTRRS];
    IA32_MTRR_PHYSBASE_REG ia32_mtrr_var_phys_base[MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS];
    IA32_MTRR_PHYSMASK_REG ia32_mtrr_var_phys_mask[MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS];
    BOOLEAN is_initialized;
    UINT32  padding; // not used
} MTRRS_ABSTRACTION_CACHED_INFO;

static MTRRS_ABSTRACTION_CACHED_INFO mtrrs_cached_info;
UINT64 remsize = 0;
UINT64 MTRR_MSBs=0;
/*---------------------------------------------------*/

UINT32 mtrrs_abstraction_get_num_of_variable_range_regs(void) {
    UINT64 num = mtrrs_cached_info.ia32_mtrrcap_reg.bits.vcnt;
    return (UINT32)num;
}

INLINE
BOOLEAN mtrrs_abstraction_are_fixed_regs_supported(void) {
    return (mtrrs_cached_info.ia32_mtrrcap_reg.bits.fix != 0);
}

INLINE
BOOLEAN mtrrs_abstraction_are_mtrrs_enabled(void) {
    return (mtrrs_cached_info.ia32_mtrr_def_type.bits.enable != 0);
}

INLINE
BOOLEAN mtrrs_abstraction_are_fixed_ranged_mtrrs_enabled(void) {
    return (mtrrs_cached_info.ia32_mtrr_def_type.bits.fixed_range_enable != 0);
}

INLINE
VMM_PHYS_MEM_TYPE mtrrs_abstraction_get_default_memory_type(void) {
    UINT64 type = mtrrs_cached_info.ia32_mtrr_def_type.bits.type;
    return (VMM_PHYS_MEM_TYPE)type;
}

INLINE
BOOLEAN mtrrs_abstraction_is_var_reg_valid(UINT32 index) {
    return (mtrrs_cached_info.ia32_mtrr_var_phys_mask[index].bits.valid != 0);
}

INLINE
UINT64 mtrrs_abstraction_get_address_from_reg(UINT32 reg_index) {
    UINT32 addr_base_low = mtrrs_cached_info.ia32_mtrr_var_phys_base[reg_index].bits.phys_base_low << MTRRS_ABS_ADDR_BASE_SHIFT;
    UINT32 addr_base_high = mtrrs_cached_info.ia32_mtrr_var_phys_base[reg_index].bits.phys_base_high;
    UINT64 addr = ((UINT64)addr_base_high << MTRRS_ABS_HIGH_ADDR_SHIFT) | addr_base_low;

    return addr;
}

INLINE
UINT64 mtrrs_abstraction_get_mask_from_reg(UINT32 reg_index) {
    UINT32 addr_mask_low = mtrrs_cached_info.ia32_mtrr_var_phys_mask[reg_index].bits.phys_mask_low << MTRRS_ABS_ADDR_BASE_SHIFT;
    UINT32 addr_mask_high = mtrrs_cached_info.ia32_mtrr_var_phys_mask[reg_index].bits.phys_mask_high;
    UINT64 addr_mask = ((UINT64)addr_mask_high << MTRRS_ABS_HIGH_ADDR_SHIFT) | addr_mask_low;

    return addr_mask;
}

INLINE
BOOLEAN mtrrs_abstraction_is_addr_covered_by_var_reg(HPA address, UINT32 reg_index) {
    UINT64 phys_base = mtrrs_abstraction_get_address_from_reg(reg_index);
    UINT64 phys_mask = mtrrs_abstraction_get_mask_from_reg(reg_index);
    UINT64 mask_base = phys_base & phys_mask;
    UINT64 mask_target = phys_mask & address;
        if (mask_base == mask_target)
        {
                remsize = (phys_base & phys_mask) + (~(phys_mask | MTRR_MSBs)) + 1 - address;

        }
    return (mask_base == mask_target);
}

INLINE
BOOLEAN mttrs_abstraction_is_type_valid(UINT64 type) {
    switch (type) {
    case VMM_PHYS_MEM_UNCACHABLE:
    case VMM_PHYS_MEM_WRITE_COMBINING:
    case VMM_PHYS_MEM_WRITE_THROUGH:
    case VMM_PHYS_MEM_WRITE_PROTECTED:
    case VMM_PHYS_MEM_WRITE_BACK:
        return TRUE;
    }
    return FALSE;
}

INLINE
BOOLEAN mtrrs_abstraction_is_IA32_MTRR_DEF_TYPE_valid(UINT64 value) {
    IA32_MTRR_DEF_TYPE_REG reg;
    reg.value = value;
    return ((reg.bits.res0 == 0) && (reg.bits.res1 == 0) && mttrs_abstraction_is_type_valid(reg.bits.type));
}

INLINE
BOOLEAN mtrrs_abstraction_is_IA32_MTRR_PHYSBASE_REG_valid(UINT64 value) {
    IA32_MTRR_PHYSBASE_REG reg;
    reg.value = value;
    return ((reg.bits.res0 == 0) && (reg.bits.res1 == 0) && mttrs_abstraction_is_type_valid(reg.bits.type));
}

INLINE
BOOLEAN mtrrs_abstraction_is_IA32_MTRR_PHYSMASK_REG_valid(UINT64 value) {
    IA32_MTRR_PHYSMASK_REG reg;
    reg.value = value;
    return ((reg.bits.res0 == 0) && (reg.bits.res1 == 0));
}

INLINE
BOOLEAN mtrrs_abstraction_is_IA32_FIXED_RANGE_REG_valid(UINT64 value) {
    IA32_FIXED_RANGE_MTRR reg;
    UINT32 i;
    reg.value = value;
    for (i = 0; i < MTRRS_ABS_NUM_OF_SUB_RANGES; i++) {
        if (!mttrs_abstraction_is_type_valid(reg.type[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN mtrrs_is_variable_mtrrr_supported(UINT32 msr_id) {

        /*
         * IA32_MTRR_PHYSBASE8 - supported only if IA32_MTRR_CAP[7:0] > 8
         * IA32_MTRR_PHYSMASK8 - supported only if IA32_MTRR_CAP[7:0] > 8
         * IA32_MTRR_PHYSBASE9 - supported only if IA32_MTRR_CAP[7:0] > 9
         * IA32_MTRR_PHYSMASK9 - supported only if IA32_MTRR_CAP[7:0] > 9
         */

        UINT32 index, i;

        /* Check if MSR is within unsupported variable MTRR range */
        if(msr_id >= IA32_MTRR_PHYSBASE8_ADDR
                && msr_id <= IA32_MTRR_MAX_PHYSMASK_ADDR) {

                for(index = IA32_MTRR_MAX_PHYSMASK_ADDR, i = 1; index > IA32_MTRR_PHYSBASE8_ADDR; index -= 2, i++) {
                        if( ((index == msr_id) || (index - 1 == msr_id)) )
                                if (mtrrs_abstraction_get_num_of_variable_range_regs() > (MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS - i) )
                                        return TRUE;
                                else
                                        return FALSE;
                }
                return TRUE; // dummy added to suppress warning, should never get here
        } else // MSR is not within unsupported variable MTRR range.
                return TRUE;
}

/*---------------------------------------------------*/
BOOLEAN mtrrs_abstraction_bsp_initialize(void) {
    UINT32 msr_addr;
    UINT32 index;

    vmm_memset(&mtrrs_cached_info, 0, sizeof(mtrrs_cached_info));
    mtrrs_cached_info.ia32_mtrrcap_reg.value = hw_read_msr(IA32_MTRRCAP_ADDR);
    mtrrs_cached_info.ia32_mtrr_def_type.value = hw_read_msr(IA32_MTRR_DEF_TYPE_ADDR);

    if (mtrrs_abstraction_are_fixed_regs_supported()) {
        mtrrs_cached_info.ia32_mtrr_fix[0].value = hw_read_msr(IA32_MTRR_FIX64K_00000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[0].start_addr = 0x0;
        mtrrs_cached_info.ia32_mtrr_fix_range[0].end_addr = 0x7ffff;

        mtrrs_cached_info.ia32_mtrr_fix[1].value = hw_read_msr(IA32_MTRR_FIX16K_80000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[1].start_addr = 0x80000;
        mtrrs_cached_info.ia32_mtrr_fix_range[1].end_addr = 0x9ffff;

        mtrrs_cached_info.ia32_mtrr_fix[2].value = hw_read_msr(IA32_MTRR_FIX16K_A0000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[2].start_addr = 0xa0000;
        mtrrs_cached_info.ia32_mtrr_fix_range[2].end_addr = 0xbffff;

        mtrrs_cached_info.ia32_mtrr_fix[3].value = hw_read_msr(IA32_MTRR_FIX4K_C0000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[3].start_addr = 0xc0000;
        mtrrs_cached_info.ia32_mtrr_fix_range[3].end_addr = 0xc7fff;

        mtrrs_cached_info.ia32_mtrr_fix[4].value = hw_read_msr(IA32_MTRR_FIX4K_C8000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[4].start_addr = 0xc8000;
        mtrrs_cached_info.ia32_mtrr_fix_range[4].end_addr = 0xcffff;

        mtrrs_cached_info.ia32_mtrr_fix[5].value = hw_read_msr(IA32_MTRR_FIX4K_D0000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[5].start_addr = 0xd0000;
        mtrrs_cached_info.ia32_mtrr_fix_range[5].end_addr = 0xd7fff;

        mtrrs_cached_info.ia32_mtrr_fix[6].value = hw_read_msr(IA32_MTRR_FIX4K_D8000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[6].start_addr = 0xd8000;
        mtrrs_cached_info.ia32_mtrr_fix_range[6].end_addr = 0xdffff;

        mtrrs_cached_info.ia32_mtrr_fix[7].value = hw_read_msr(IA32_MTRR_FIX4K_E0000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[7].start_addr = 0xe0000;
        mtrrs_cached_info.ia32_mtrr_fix_range[7].end_addr = 0xe7fff;

        mtrrs_cached_info.ia32_mtrr_fix[8].value = hw_read_msr(IA32_MTRR_FIX4K_E8000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[8].start_addr = 0xe8000;
        mtrrs_cached_info.ia32_mtrr_fix_range[8].end_addr = 0xeffff;

        mtrrs_cached_info.ia32_mtrr_fix[9].value = hw_read_msr(IA32_MTRR_FIX4K_F0000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[9].start_addr = 0xf0000;
        mtrrs_cached_info.ia32_mtrr_fix_range[9].end_addr = 0xf7fff;

        mtrrs_cached_info.ia32_mtrr_fix[10].value = hw_read_msr(IA32_MTRR_FIX4K_F8000_ADDR);
        mtrrs_cached_info.ia32_mtrr_fix_range[10].start_addr = 0xf8000;
        mtrrs_cached_info.ia32_mtrr_fix_range[10].end_addr = 0xfffff;

    }

    for (msr_addr = IA32_MTRR_PHYSBASE0_ADDR, index = 0; index < mtrrs_abstraction_get_num_of_variable_range_regs(); msr_addr += 2, index++) {
        if (msr_addr > IA32_MTRR_MAX_PHYSMASK_ADDR) {
                VMM_LOG(mask_uvmm,level_error, "BSP: ERROR: MTRRs Abstraction: Variable MTRRs count > %d", MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS);
            VMM_DEADLOOP();
        }

        mtrrs_cached_info.ia32_mtrr_var_phys_base[index].value = hw_read_msr(msr_addr);
        mtrrs_cached_info.ia32_mtrr_var_phys_mask[index].value = hw_read_msr(msr_addr + 1);
    }


//      {
//              UINT64 i=1;
//              MTRR_MSBs = 0;
//              i = i << 63;
//              while (( mtrrs_cached_info.ia32_mtrr_var_phys_mask[0].value & i) == 0)
//              {
//                      MTRR_MSBs = MTRR_MSBs + i;
//                      i = i >> 1;
//                      if (i == 0)
//                              break;
//              }
//      }
   
    MTRR_MSBs = ~((UINT64)(((UINT64)1 << addr_get_physical_address_size()) - 1));

    mtrrs_cached_info.is_initialized = TRUE;
    return TRUE;
}

BOOLEAN mtrrs_abstraction_ap_initialize(void) {
    UINT32 msr_addr;
    UINT32 index;

    if (!mtrrs_cached_info.is_initialized) {
        VMM_LOG(mask_anonymous, level_error,"ERROR: MTRRs Abstraction: Initializing AP before BSP\n");
        goto failed;
    }

    if (mtrrs_cached_info.ia32_mtrrcap_reg.value != hw_read_msr(IA32_MTRRCAP_ADDR)) {
        VMM_LOG(mask_anonymous, level_error,"ERROR: MTRRs Abstraction: IA32_MTRRCAP doesn't match\n");
        goto failed;
    }

    if (mtrrs_cached_info.ia32_mtrr_def_type.value != hw_read_msr(IA32_MTRR_DEF_TYPE_ADDR)) {
        VMM_LOG(mask_anonymous, level_error,"ERROR: MTRRs Abstraction: IA32_MTRR_DEF_TYPE doesn't match\n");
        goto failed;
    }

    if (mtrrs_abstraction_are_fixed_regs_supported()) {
        if ((mtrrs_cached_info.ia32_mtrr_fix[0].value != hw_read_msr(IA32_MTRR_FIX64K_00000_ADDR)) ||
            (mtrrs_cached_info.ia32_mtrr_fix[1].value != hw_read_msr(IA32_MTRR_FIX16K_80000_ADDR)) ||
            (mtrrs_cached_info.ia32_mtrr_fix[2].value != hw_read_msr(IA32_MTRR_FIX16K_A0000_ADDR)) ||
            (mtrrs_cached_info.ia32_mtrr_fix[3].value != hw_read_msr(IA32_MTRR_FIX4K_C0000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[4].value != hw_read_msr(IA32_MTRR_FIX4K_C8000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[5].value != hw_read_msr(IA32_MTRR_FIX4K_D0000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[6].value != hw_read_msr(IA32_MTRR_FIX4K_D8000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[7].value != hw_read_msr(IA32_MTRR_FIX4K_E0000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[8].value != hw_read_msr(IA32_MTRR_FIX4K_E8000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[9].value != hw_read_msr(IA32_MTRR_FIX4K_F0000_ADDR))  ||
            (mtrrs_cached_info.ia32_mtrr_fix[10].value != hw_read_msr(IA32_MTRR_FIX4K_F8000_ADDR))) {

            VMM_LOG(mask_anonymous, level_error,"ERROR: MTRRs Abstraction: One (or more) of the fixed range MTRRs doesn't match\n");

            goto failed;
        }
    }

    for (msr_addr = IA32_MTRR_PHYSBASE0_ADDR, index = 0; index < mtrrs_abstraction_get_num_of_variable_range_regs(); msr_addr += 2, index++) {
        if (msr_addr > IA32_MTRR_MAX_PHYSMASK_ADDR) {
                VMM_LOG(mask_uvmm,level_error, "AP: ERROR: MTRRs Abstraction: Variable MTRRs count > %d", MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS);
            VMM_DEADLOOP();
        }

        if ((mtrrs_cached_info.ia32_mtrr_var_phys_base[index].value != hw_read_msr(msr_addr)) ||
            (mtrrs_cached_info.ia32_mtrr_var_phys_mask[index].value != hw_read_msr(msr_addr + 1))) {

            VMM_LOG(mask_anonymous, level_error,"ERROR: MTRRs Abstraction: One (or more) of the variable range MTRRs doesn't match\n");
            goto failed;
        }
    }

    return TRUE;
failed:
    VMM_ASSERT(0);
    return FALSE;
}


VMM_PHYS_MEM_TYPE mtrrs_abstraction_get_memory_type(HPA address) {
    UINT32 index;
    UINT32 var_mtrr_match_bitmap;
    VMM_PHYS_MEM_TYPE type = VMM_PHYS_MEM_UNDEFINED;
        UINT64 remsize_back = 0, range_base = 0;
    VMM_PHYS_MEM_TYPE type_back = VMM_PHYS_MEM_UNDEFINED;

        remsize = 0;
    VMM_ASSERT(mtrrs_cached_info.is_initialized);

    if (!mtrrs_abstraction_are_mtrrs_enabled()) {
        return VMM_PHYS_MEM_UNCACHABLE;
    }

    if (mtrrs_abstraction_are_fixed_regs_supported() &&
        mtrrs_abstraction_are_fixed_ranged_mtrrs_enabled() &&
        (address <= mtrrs_cached_info.ia32_mtrr_fix_range[MTRRS_ABS_NUM_OF_FIXED_RANGE_MTRRS - 1].end_addr)) {

        // Find proper fixed range MTRR
        for (index = 0; index < MTRRS_ABS_NUM_OF_FIXED_RANGE_MTRRS; index++) {
            if (address <= mtrrs_cached_info.ia32_mtrr_fix_range[index].end_addr) {
                // Find proper sub-range
                UINT64 offset = address - mtrrs_cached_info.ia32_mtrr_fix_range[index].start_addr;
                UINT32 size = mtrrs_cached_info.ia32_mtrr_fix_range[index].end_addr + 1 - mtrrs_cached_info.ia32_mtrr_fix_range[index].start_addr;
                UINT32 sub_range_size = size / MTRRS_ABS_NUM_OF_SUB_RANGES;
                UINT64 sub_range_index = offset / sub_range_size;
                                remsize = (sub_range_index+1) * sub_range_size - offset;
                VMM_ASSERT((size % MTRRS_ABS_NUM_OF_SUB_RANGES) == 0);
                VMM_ASSERT(sub_range_index < MTRRS_ABS_NUM_OF_SUB_RANGES);
                return (VMM_PHYS_MEM_TYPE)mtrrs_cached_info.ia32_mtrr_fix[index].type[sub_range_index];
            }
        }
        VMM_ASSERT(0); // mustn't reach here
    }

    var_mtrr_match_bitmap = 0;

    for (index = 0; index < mtrrs_abstraction_get_num_of_variable_range_regs(); index++) {
        if (index >= MTRRS_ABS_NUM_OF_VAR_RANGE_MTRRS) {
            break;
        }

        if (!mtrrs_abstraction_is_var_reg_valid(index)) {
            continue;
        }
        
        if (mtrrs_abstraction_is_addr_covered_by_var_reg(address, index)) {
            type = (VMM_PHYS_MEM_TYPE)mtrrs_cached_info.ia32_mtrr_var_phys_base[index].bits.type;
            BIT_SET(var_mtrr_match_bitmap, type);
                        
            if (remsize_back > 0) {
                if (type == VMM_PHYS_MEM_UNCACHABLE || type_back == VMM_PHYS_MEM_UNCACHABLE) {
                    if (type_back != VMM_PHYS_MEM_UNCACHABLE) {
                        remsize_back = remsize;
                    }
                    if (type != VMM_PHYS_MEM_UNCACHABLE) {       
                        remsize =0;
                    }
                    if (type == VMM_PHYS_MEM_UNCACHABLE && type_back == VMM_PHYS_MEM_UNCACHABLE)
                        remsize_back = (remsize_back > remsize) ? remsize_back : remsize;

                    type_back = VMM_PHYS_MEM_UNCACHABLE;
                    remsize =0;
                }
                else {
                    remsize_back = (remsize_back > remsize) ? remsize : remsize_back;
                    type_back = type;
                    remsize = 0;
                }
            }
            else {
                remsize_back = remsize;
                remsize = 0;
                type_back = type;
            }
        }
        else {
            range_base = mtrrs_abstraction_get_address_from_reg(index);
            
            if (address < range_base && address + remsize_back > range_base) {
                remsize_back = range_base - address;
            }
        }
    }
    remsize = remsize_back;

    if (0 == var_mtrr_match_bitmap) {
        // not described by any MTRR, return default memory type
        return mtrrs_abstraction_get_default_memory_type();
    }
    else if (IS_POW_OF_2(var_mtrr_match_bitmap)) {
        // described by single MTRR, type contains the proper value
        return type;
    }
    else if (BIT_GET(var_mtrr_match_bitmap, VMM_PHYS_MEM_UNCACHABLE)) {
        // fall in multiple ranges, UC wins
        return VMM_PHYS_MEM_UNCACHABLE;
    }
    else if ((BIT_VALUE64(VMM_PHYS_MEM_WRITE_THROUGH) | BIT_VALUE64(VMM_PHYS_MEM_WRITE_BACK))
        == var_mtrr_match_bitmap) {
        // fall in WT + WB, WT wins.
        return VMM_PHYS_MEM_WRITE_THROUGH;
    }

    // improper MTRR setting
    VMM_LOG(mask_anonymous, level_error,
        "FATAL: MTRRs Abstraction: Overlapping variable MTRRs have confilting types\n");
    VMM_DEADLOOP();
    return VMM_PHYS_MEM_UNDEFINED;
}

VMM_PHYS_MEM_TYPE mtrrs_abstraction_get_range_memory_type(HPA address, OUT UINT64 *size,UINT64 totalsize)
{
    VMM_PHYS_MEM_TYPE first_page_mem_type, mem_type;
    UINT64 range_size = 0;
        remsize=0;

    first_page_mem_type = mtrrs_abstraction_get_memory_type(address);

    for(mem_type = first_page_mem_type;
        (mem_type == first_page_mem_type) && (range_size<totalsize);
        mem_type = mtrrs_abstraction_get_memory_type(address + range_size)) {
        if (remsize != 0)
           range_size += remsize;
        else
            range_size += 4 KILOBYTES;
    }
    if(size != NULL) {
        *size = range_size;
    }
    return first_page_mem_type;
}

BOOLEAN mtrrs_abstraction_track_mtrr_update(UINT32 mtrr_index, UINT64 value) {

    if (mtrr_index == IA32_MTRR_DEF_TYPE_ADDR) {
        if (!mtrrs_abstraction_is_IA32_MTRR_DEF_TYPE_valid(value)) {
            return FALSE;
        }
        mtrrs_cached_info.ia32_mtrr_def_type.value = value;
        return TRUE;
    }
    if ((mtrr_index >= IA32_MTRR_FIX64K_00000_ADDR) && (mtrr_index <= IA32_MTRR_FIX4K_F8000_ADDR)) {
        UINT32 fixed_index = (~((UINT32)0));
        switch(mtrr_index) {

        case IA32_MTRR_FIX64K_00000_ADDR:
            fixed_index = 0;
            break;
        case IA32_MTRR_FIX16K_80000_ADDR:
            fixed_index = 1;
            break;
        case IA32_MTRR_FIX16K_A0000_ADDR:
            fixed_index = 2;
            break;
        case IA32_MTRR_FIX4K_C0000_ADDR:
            fixed_index = 3;
            break;
        case IA32_MTRR_FIX4K_C8000_ADDR:
            fixed_index = 4;
            break;
        case IA32_MTRR_FIX4K_D0000_ADDR:
            fixed_index = 5;
            break;
        case IA32_MTRR_FIX4K_D8000_ADDR:
            fixed_index = 6;
            break;
        case IA32_MTRR_FIX4K_E0000_ADDR:
            fixed_index = 7;
            break;
        case IA32_MTRR_FIX4K_E8000_ADDR:
            fixed_index = 8;
            break;
        case IA32_MTRR_FIX4K_F0000_ADDR:
            fixed_index = 9;
            break;
        case IA32_MTRR_FIX4K_F8000_ADDR:
            fixed_index = 10;
            break;
        default:
            VMM_ASSERT(0);
            return FALSE;
        }

        if (!mtrrs_abstraction_is_IA32_FIXED_RANGE_REG_valid(value)) {
            return FALSE;
        }
        mtrrs_cached_info.ia32_mtrr_fix[fixed_index].value = value;
        return TRUE;
    }


    if ((mtrr_index >= IA32_MTRR_PHYSBASE0_ADDR) && (mtrr_index <= IA32_MTRR_MAX_PHYSMASK_ADDR)){
        BOOLEAN is_phys_base = ((mtrr_index % 2) == 0);
        if (is_phys_base) {
            UINT32 phys_base_index = (mtrr_index - IA32_MTRR_PHYSBASE0_ADDR) / 2;
            if (!mtrrs_abstraction_is_IA32_MTRR_PHYSBASE_REG_valid(value)) {
                return FALSE;
            }
            mtrrs_cached_info.ia32_mtrr_var_phys_base[phys_base_index].value = value;
        }
        else {
            UINT32 phys_mask_index = (mtrr_index - IA32_MTRR_PHYSMASK0_ADDR) / 2;
            if (!mtrrs_abstraction_is_IA32_MTRR_PHYSMASK_REG_valid(value)) {
                return FALSE;
            }
            mtrrs_cached_info.ia32_mtrr_var_phys_mask[phys_mask_index].value = value;
        }
        return TRUE;
    }

    return FALSE;
}
