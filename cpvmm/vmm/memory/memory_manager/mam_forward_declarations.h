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

#ifndef MAM_FORWAD_DECLARATIONS_H
#define MAM_FORWAD_DECLARATIONS_H

static UINT64 mam_get_size_covered_by_level1_entry(void);
static UINT64 mam_get_size_covered_by_level2_entry(void);
static UINT64 mam_get_size_covered_by_level3_entry(void);
static UINT64 mam_get_size_covered_by_level4_entry(void);
static UINT32 mam_get_level1_entry_index(IN UINT64 address);
static UINT32 mam_get_level2_entry_index(IN UINT64 address);
static UINT32 mam_get_level3_entry_index(IN UINT64 address);
static UINT32 mam_get_level4_entry_index(IN UINT64 address);
static const MAM_LEVEL_OPS* mam_get_non_existing_ops(void);
static const MAM_LEVEL_OPS* mam_get_level1_ops(void);
static const MAM_LEVEL_OPS* mam_get_level2_ops(void);
static const MAM_LEVEL_OPS* mam_get_level3_ops(void);
static const MAM_LEVEL_OPS* mam_get_level4_ops(void);

static UINT64 mam_get_address_from_leaf_internal_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static UINT64 mam_get_address_from_leaf_page_table_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static UINT64 mam_get_address_from_leaf_ept_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static UINT64 mam_get_address_from_leaf_vtdpt_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static MAM_ATTRIBUTES mam_get_attributes_from_internal_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static MAM_ATTRIBUTES mam_get_attributes_from_page_table_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static MAM_ATTRIBUTES mam_get_attributes_from_ept_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static MAM_ATTRIBUTES mam_get_attributes_from_vtdpt_entry(IN MAM_ENTRY* entry, 
                        IN const MAM_LEVEL_OPS* level_ops);
static MAM_HVA mam_get_table_pointed_by_internal_enty(IN MAM_ENTRY* entry); 
static MAM_HVA mam_get_table_pointed_by_page_table_entry(IN MAM_ENTRY* entry);
static MAM_HVA mam_get_table_pointed_by_ept_entry(IN MAM_ENTRY* entry);
static MAM_HVA mam_get_table_pointed_by_vtdpt_entry(IN MAM_ENTRY* entry);
static BOOLEAN mam_is_internal_entry_present(IN MAM_ENTRY* entry);
static BOOLEAN mam_is_page_table_entry_present(IN MAM_ENTRY* entry);
static BOOLEAN mam_is_ept_entry_present(IN MAM_ENTRY* entry);
static BOOLEAN mam_is_vtdpt_entry_present(IN MAM_ENTRY* entry);
static BOOLEAN mam_can_be_leaf_internal_entry(IN MAM* mam, 
        IN const MAM_LEVEL_OPS* level_ops, IN UINT64 requested_size, IN UINT64 tgt_addr);
static BOOLEAN mam_can_be_leaf_page_table_entry(IN MAM* mam, 
        IN const MAM_LEVEL_OPS* level_ops, IN UINT64 requested_size, IN UINT64 tgt_addr);
static BOOLEAN mam_can_be_leaf_ept_entry(IN MAM* mam, 
        IN const MAM_LEVEL_OPS* level_ops, IN UINT64 requested_size, IN UINT64 tgt_addr);
static BOOLEAN mam_can_be_leaf_vtdpt_entry(IN MAM* mam, 
        IN const MAM_LEVEL_OPS* level_ops, IN UINT64 requested_size, IN UINT64 tgt_addr);
static void mam_update_leaf_internal_entry(IN MAM_ENTRY* entry, IN UINT64 addr,
                    IN MAM_ATTRIBUTES attr, IN const MAM_LEVEL_OPS* level_ops);
static void mam_update_leaf_page_table_entry(IN MAM_ENTRY* entry, IN UINT64 addr,
                    IN MAM_ATTRIBUTES attr, IN const MAM_LEVEL_OPS* level_ops);
static void mam_update_leaf_ept_entry(IN MAM_ENTRY* entry, IN UINT64 addr,
                    IN MAM_ATTRIBUTES attr, IN const MAM_LEVEL_OPS* level_ops);
static void mam_update_leaf_vtdpt_entry(IN MAM_ENTRY* entry,
                    IN UINT64 addr, IN MAM_ATTRIBUTES attr,
                    IN const MAM_LEVEL_OPS* level_ops);
static void mam_update_inner_internal_entry(MAM* mam, MAM_ENTRY* entry, 
                    MAM_HVA next_table, const MAM_LEVEL_OPS* level_ops);
static void mam_update_inner_page_table_entry(MAM* mam, MAM_ENTRY* entry, 
                    MAM_HVA next_table, const MAM_LEVEL_OPS* level_ops);
static void mam_update_inner_ept_entry(MAM* mam, MAM_ENTRY* entry, 
                    MAM_HVA next_table, const MAM_LEVEL_OPS* level_ops);
static void mam_update_inner_vtdpt_entry(MAM* mam, MAM_ENTRY* entry, 
                    MAM_HVA next_table, const MAM_LEVEL_OPS* level_ops);
static void mam_update_attributes_in_leaf_internal_entry(MAM_ENTRY* entry, 
                    MAM_ATTRIBUTES attrs, const MAM_LEVEL_OPS* level_ops);
static void mam_update_attributes_in_leaf_page_table_entry(MAM_ENTRY* entry, 
                    MAM_ATTRIBUTES attrs, const MAM_LEVEL_OPS* level_ops);
static void mam_update_attributes_in_leaf_ept_entry(MAM_ENTRY* entry, 
                    MAM_ATTRIBUTES attrs, const MAM_LEVEL_OPS* level_ops);
static void mam_update_attributes_in_leaf_vtdpt_entry(MAM_ENTRY* entry, 
                    MAM_ATTRIBUTES attrs, const MAM_LEVEL_OPS* level_ops);
static MAM_ENTRY_TYPE mam_get_leaf_internal_entry_type(void);
static MAM_ENTRY_TYPE mam_get_leaf_page_table_entry_type(void);
static MAM_ENTRY_TYPE mam_get_leaf_ept_entry_type(void);
static MAM_ENTRY_TYPE mam_get_leaf_vtdpt_entry_type(void);
static void mam_destroy_table(IN MAM_HVA table);

#endif
