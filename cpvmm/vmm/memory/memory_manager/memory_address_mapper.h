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

#ifndef MEMORY_ADDRESS_MAPPER_H
#define MEMORY_ADDRESS_MAPPER_H

#include <vmm_defs.h>
#include <lock.h>

typedef UINT64 MAM_HVA;
typedef UINT64 MAM_HPA;


typedef union MAM_ENTRY_U {
    struct {
        UINT32
                      :9,
            avl       :3, // This bits are available in all types of entries except VT-d page tables and used in order to identify type of entry (MAM_ENTRY_TYPE)
            addr_low  :20;
        UINT32
            addr_high :8,
                      :24;
    } any_entry;

    struct {
        UINT32
            present    :1,
            attributes :8,
            /*avl*/    :3,
            addr_low   :20;
        UINT32
            addr_high  :8,
                       :24;
    } mam_internal_entry;

    struct {
        UINT32
            present   :1,
            writable  :1,
            user      :1,
            pwt       :1,
            pcd       :1,
                      :2,
            ps_or_pat :1,
            global    :1,
            avl       :3,
            addr_low  :20;
        UINT32
            addr_high :8,
                      :23,
            exb       :1;
    } page_table_entry;

    struct {
        UINT32
            readable   :1,
            writable   :1,
            executable :1,
            emt        :3,
            igmt       :1,
            sp         :1,
            avl        :4,
            addr_low   :20;
        UINT32
            addr_high  :8,
                       :23,
            suppress_ve:1;
    } ept_entry;


    struct {
        UINT32
            readable   :1,
            writable   :1,
					   :5,
            sp         :1,
            avl_1      :1, /* set for leaf entry */
            avl_2      :2, /* MAM_INNER_VTDPT_ENTRY */
            snoop      :1,
            addr_low   :20;
        UINT32
            addr_high  :8,
                       :22,
            tm         :1,
                       :1;
    } vtdpt_entry;

    struct {
        struct {
            UINT32
            must_be_zero0 :9,
            avl           :3,
            must_be_zero1 :20;
        } low_part;
        struct {
            UINT32
            reason        :31,
            suppress_ve   :1;
        } high_part;
    } invalid_entry;

    UINT64 uint64;
} MAM_ENTRY;

typedef enum {
    MAM_GENERAL_MAPPING,
    MAM_PAGE_TABLES_COMPLIANT_MAPPING,
    MAM_EPT_COMPLIANT_MAPPING
} MAM_MAPPING_TYPE;

typedef enum {
    MAM_PAGE_TABLE_ENTRY = 0x0, // 000
    MAM_EPT_ENTRY = 0x1,        // 001
    MAM_INTERNAL_ENTRY = 0x2,   // 010
    MAM_VTDPT_ENTRY = 0x3       // 011
} MAM_BASIC_ENTRY_TYPE;

#define MAM_INNER_ENTRY_TYPE_MASK 0x3	//011

#define MAM_LEAF_ENTRY_TYPE_MASK 0x4 // 100

// Note that this entry type will reside in three avl bits in entry. In oder to check whether it is leaf just check the MSB (third bit)
typedef enum {
    MAM_INNER_PAGE_TABLE_ENTRY = MAM_PAGE_TABLE_ENTRY,                              // 000
    MAM_INNER_EPT_ENTRY = MAM_EPT_ENTRY,                                            // 001
    MAM_INNER_INTERNAL_ENTRY = MAM_INTERNAL_ENTRY,                                  // 010
    MAM_INNER_VTDPT_ENTRY = MAM_VTDPT_ENTRY,										// 011
    MAM_LEAF_PAGE_TABLE_ENTRY = (MAM_PAGE_TABLE_ENTRY | MAM_LEAF_ENTRY_TYPE_MASK),  // 100
    MAM_LEAF_EPT_ENTRY = (MAM_EPT_ENTRY | MAM_LEAF_ENTRY_TYPE_MASK),                // 101
    MAM_LEAF_INTERNAL_ENTRY = (MAM_INTERNAL_ENTRY | MAM_LEAF_ENTRY_TYPE_MASK),      // 110
	MAM_LEAF_VTDPT_ENTRY = (MAM_VTDPT_ENTRY | MAM_LEAF_ENTRY_TYPE_MASK)				// 111
} MAM_ENTRY_TYPE;

typedef enum {
    MAM_OVERWRITE_ADDR_AND_ATTRS,
    MAM_SET_ATTRS,
    MAM_CLEAR_ATTRS,
//RTDBEUG
	MAM_OVERWRITE_ATTRS,
} MAM_UPDATE_OP;

/*******************************************************************
*  The adjusted guest address widths corresponding to various bit indices of 
*  SAGAW field are:
* 0: 30-bit AGAW (2-level page-table)
* 1: 39-bit AGAW (3-level page-table)
* 2: 48-bit AGAW (4-level page-table)
* 3: 57-bit AGAW (5-level page-table)
* 4: 64-bit AGAW (6-level page-table)
*******************************************************************/
typedef enum{
    MAM_VTDPT_LEVEL_2 = 0x0,
    MAM_VTDPT_LEVEL_3 = 0x1,
    MAM_VTDPT_LEVEL_4 = 0x2,
    MAM_VTDPT_LEVEL_5 = 0x3,
    MAM_VTDPT_LEVEL_6 = 0x4,
} MAM_VTDPT_LEVEL;

//-----------------------------------------------------------------------------

struct MAM_S;
typedef struct MAM_S MAM;

struct MAM_LEVEL_OPS_S;
typedef struct MAM_LEVEL_OPS_S MAM_LEVEL_OPS;

struct MAM_ENTRY_OPS_S;
typedef struct MAM_ENTRY_OPS_S MAM_ENTRY_OPS;

//-----------------------------------------------------------------------------

typedef UINT64 (*MAM_GET_SIZE_COVERED_BY_ENTRY_FN)(void);
typedef UINT32 (*MAM_GET_ENTRY_INDEX_FN)(UINT64);
typedef const MAM_LEVEL_OPS* (*MAM_GET_LOWER_LEVEL_OPS_FN)(void);
typedef const MAM_LEVEL_OPS* (*MAM_GET_UPPER_LEVEL_OPS_FN)(void);

struct MAM_LEVEL_OPS_S {
    MAM_GET_SIZE_COVERED_BY_ENTRY_FN mam_get_size_covered_by_entry_fn;
    MAM_GET_ENTRY_INDEX_FN mam_get_entry_index_fn;
    MAM_GET_LOWER_LEVEL_OPS_FN mam_get_lower_level_ops_fn;
    MAM_GET_UPPER_LEVEL_OPS_FN mam_get_upper_level_ops_fn;
};

//-----------------------------------------------------------------------------

typedef UINT64 (*MAM_GET_ADDRESS_FROM_LEAF_ENTRY)(MAM_ENTRY*, const MAM_LEVEL_OPS*);
typedef MAM_ATTRIBUTES (*MAM_GET_ATTRIBUTES_FROM_ENTRY)(MAM_ENTRY*, const MAM_LEVEL_OPS*);
typedef MAM_HVA (*MAM_GET_TABLE_POINTED_BY_ENTRY_FN)(MAM_ENTRY*);
typedef BOOLEAN (*MAM_IS_ENTRY_PRESENT_FN)(MAM_ENTRY*);
typedef BOOLEAN (*MAM_CAN_BE_LEAF_ENTRY_FN)(MAM*, const MAM_LEVEL_OPS*, UINT64, UINT64);
typedef void (*MAM_UPDATE_LEAF_ENTRY_FN)(MAM_ENTRY*, UINT64, MAM_ATTRIBUTES, const MAM_LEVEL_OPS*);
typedef void (*MAM_UPDATE_INNER_LEVEL_ENTRY_FN)(MAM*, MAM_ENTRY*, MAM_HVA, const MAM_LEVEL_OPS*);
typedef void (*MAM_UPDATE_ATTRIBUTES_IN_LEAF_ENTRY_FN)(MAM_ENTRY*, MAM_ATTRIBUTES, const MAM_LEVEL_OPS*);
typedef MAM_ENTRY_TYPE (*MAM_GET_LEAF_ENTRY_TYPE_FN)(void);

struct MAM_ENTRY_OPS_S {
    MAM_GET_ADDRESS_FROM_LEAF_ENTRY mam_get_address_from_leaf_entry_fn;
    MAM_GET_ATTRIBUTES_FROM_ENTRY mam_get_attributes_from_entry_fn;
    MAM_GET_TABLE_POINTED_BY_ENTRY_FN mam_get_table_pointed_by_entry_fn;
    MAM_IS_ENTRY_PRESENT_FN mam_is_entry_present_fn;
    MAM_CAN_BE_LEAF_ENTRY_FN mam_can_be_leaf_entry_fn;
    MAM_UPDATE_LEAF_ENTRY_FN mam_update_leaf_entry_fn;
    MAM_UPDATE_INNER_LEVEL_ENTRY_FN mam_update_inner_level_entry_fn;
    MAM_UPDATE_ATTRIBUTES_IN_LEAF_ENTRY_FN mam_update_attributes_in_leaf_entry_fn;
    MAM_GET_LEAF_ENTRY_TYPE_FN mam_get_leaf_entry_type_fn;
};

//-----------------------------------------------------------------------------

struct MAM_S {
    MAM_HVA first_table;
    MAM_LEVEL_OPS* first_table_ops;
    MAM_ATTRIBUTES inner_level_attributes;
    MAM_EPT_SUPER_PAGE_SUPPORT ept_supper_page_support;
    VMM_LOCK update_lock;
    volatile UINT32 update_counter;
    UINT32 update_on_cpu;
    BOOLEAN is_32bit_page_tables;
    MAM_VTDPT_SUPER_PAGE_SUPPORT vtdpt_supper_page_support;
    MAM_VTDPT_SNOOP_BEHAVIOR vtdpt_snoop_behavior;
	MAM_VTDPT_TRANS_MAPPING vtdpt_trans_mapping;
    UINT8 ept_hw_ve_support;
    MAM_MEMORY_RANGES_ITERATOR last_iterator;
    UINT64 last_range_size;
};


#define MAM_NUM_OF_ENTRIES_IN_TABLE (PAGE_4KB_SIZE / sizeof(MAM_ENTRY))
#define MAM_TABLE_ADDRESS_SHIFT 12
#define MAM_TABLE_ADDRESS_HIGH_SHIFT 32
#define MAM_LEVEL1_TABLE_POS 12
#define MAM_LEVEL2_TABLE_POS 21
#define MAM_LEVEL3_TABLE_POS 30
#define MAM_LEVEL4_TABLE_POS 39
#define MAM_ENTRY_INDEX_MASK 0x1ff
#define MAM_PAT_BIT_POS_IN_PAT_INDEX 2
#define MAM_PCD_BIT_POS_IN_PAT_INDEX 1
#define MAM_PWT_BIT_POS_IN_PAT_INDEX 0
#define MAM_NUM_OF_PDPTES_IN_32_BIT_MODE 4
#define MAM_INVALID_ADDRESS (~((UINT64)0))
#define MAM_PAGE_1GB_MASK 0x3fffffff
#define MAM_PAGE_512GB_MASK (UINT64)0x7fffffffff
#define MAM_INVALID_CPU_ID (~((UINT32)0))
// vmm only support 48 bit guest virtual address, the high 16 bits should be all zeros
#define MAM_MAX_SUPPORTED_ADDRESS (UINT64)0xffffffffffff

#endif
