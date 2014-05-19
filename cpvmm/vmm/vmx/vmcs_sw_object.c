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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMCS_SW_OBJECT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMCS_SW_OBJECT_C, __condition)
#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "memory_allocator.h"
#include "cache64.h"
#include "vmm_objects.h"
#include "guest.h"
#include "guest_cpu.h"
#include "gpm_api.h"
#include "host_memory_manager_api.h"
#include "vmcs_api.h"
#include "vmcs_internal.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#pragma warning( disable: 4100 )

typedef struct _VMCS_SOFTWARE_OBJECT {
    struct _VMCS_OBJECT vmcs_base[1];
    CACHE64_OBJECT      cache;
    GUEST_CPU_HANDLE    gcpu;
    ADDRESS             gpa;    // if !=0 then it's original GPA
} VMCS_SOFTWARE_OBJECT;

static UINT64   vmcs_sw_read(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id);
static void     vmcs_sw_write(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value);
static void     vmcs_sw_flush_to_cpu(const struct _VMCS_OBJECT *vmcs);
static BOOLEAN  vmcs_sw_is_dirty(const struct _VMCS_OBJECT *vmcs);
static GUEST_CPU_HANDLE vmcs_sw_get_owner(const struct _VMCS_OBJECT *vmcs);

static void     vmcs_sw_add_msr_to_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
static void     vmcs_sw_add_msr_to_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
#if 0
static void     vmcs_sw_add_msr_to_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);
#endif
static void     vmcs_sw_add_msr_to_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, UINT64 value);

static void     vmcs_sw_delete_msr_from_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
static void     vmcs_sw_delete_msr_from_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
static void     vmcs_sw_delete_msr_from_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);
static void     vmcs_sw_delete_msr_from_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, UINT32 msr_index);

static void     vmcs_0_flush_to_memory(struct _VMCS_OBJECT *vmcs);
static void     vmcs_1_flush_to_memory(struct _VMCS_OBJECT *vmcs);
static void     vmcs_0_destroy(struct _VMCS_OBJECT *vmcs);
static void     vmcs_1_destroy(struct _VMCS_OBJECT *vmcs);
static void     vmcs_copy_extra_buffer( void *dst, const struct _VMCS_OBJECT *vmcs_src,
                    VMCS_FIELD field, UINT32 bytes_to_copy);

static void vmcs_0_copy_msr_list_to_merged(struct _VMCS_OBJECT *merged_vmcs,
                        struct _VMCS_SOFTWARE_OBJECT* sw_vmcs, VMCS_FIELD address_field,
                        VMCS_FIELD count_field, VMCS_ADD_MSR_FUNC add_msr_func)
{
    IA32_VMX_MSR_ENTRY* msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmcs_read(sw_vmcs->vmcs_base, address_field);
    UINT32 msr_list_count = (UINT32)vmcs_read(sw_vmcs->vmcs_base, count_field);
    UINT32 i;

    for (i = 0; i < msr_list_count; i++) {
        add_msr_func(merged_vmcs, msr_list_ptr[i].MsrIndex, msr_list_ptr[i].MsrData);
    }
}

static void vmcs_0_take_msr_list_from_merged(VMCS_SOFTWARE_OBJECT *vmcs_0,
                  struct _VMCS_OBJECT *merged_vmcs, VMCS_FIELD address_field,
                  VMCS_FIELD count_field)
{
    UINT64 addr_hpa = vmcs_read(merged_vmcs, address_field);
    UINT64 addr_hva;
    UINT64 count_value;

    if (VMCS_INVALID_ADDRESS == addr_hpa) {
        addr_hva = VMCS_INVALID_ADDRESS;
        count_value = 0;
    }
    else if ( !hmm_hpa_to_hva(addr_hpa, &addr_hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Failed translate HPA(%P) to HVA\n", __FUNCTION__);
        VMM_DEADLOOP();
        addr_hva = VMCS_INVALID_ADDRESS;
        count_value = 0;
    }
    else {
        count_value = vmcs_read(merged_vmcs, count_field);
        VMM_ASSERT(addr_hva == ALIGN_BACKWARD(addr_hva, sizeof(IA32_VMX_MSR_ENTRY)));
    }

    vmcs_write(vmcs_0->vmcs_base, address_field, addr_hva);
    vmcs_write(vmcs_0->vmcs_base, count_field, count_value);
}

struct _VMCS_OBJECT * vmcs_0_create(struct _VMCS_OBJECT *vmcs_origin)
{
    VMCS_SOFTWARE_OBJECT   *vmcs_clone;
    void                   *io_a_page = NULL;
    void                   *io_b_page = NULL;
    void                   *msr_page = NULL;
    VMCS_FIELD              field_id;

    vmcs_clone = vmm_malloc(sizeof(*vmcs_clone));
    if (NULL == vmcs_clone) {
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }

    vmcs_clone->cache = cache64_create(VMCS_FIELD_COUNT);
    if (NULL == vmcs_clone->cache) {
        vmm_mfree(vmcs_clone);
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }

    // allocate VMCS extra pages, which exist at origin VMCS
    // and write them back into clone vmcs
    // translation HVA->HPA is not necessary, since
    // these pages are never applied to hardware

    if (NULL == (io_a_page = vmm_page_alloc(1)) ||  NULL == (io_b_page = vmm_page_alloc(1))
          ||  NULL == (msr_page = vmm_page_alloc(1))) {
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation of extra pages failed\n", __FUNCTION__);
        if (NULL != io_a_page)              vmm_page_free(io_a_page);
        if (NULL != io_b_page)              vmm_page_free(io_b_page);
        if (NULL != msr_page)               vmm_page_free(msr_page);
        cache64_destroy(vmcs_clone->cache);

        vmm_mfree(vmcs_clone);

        return NULL;
    }

    vmcs_clone->gcpu = vmcs_get_owner(vmcs_origin);
    vmcs_clone->gpa  = 0;

#ifdef JLMDEBUG
    bprint("about to set vmcs entries in object\n");
#endif
    vmcs_clone->vmcs_base->vmcs_read = vmcs_sw_read;
    vmcs_clone->vmcs_base->vmcs_write = vmcs_sw_write;
    vmcs_clone->vmcs_base->vmcs_flush_to_cpu = vmcs_sw_flush_to_cpu;
    vmcs_clone->vmcs_base->vmcs_is_dirty = vmcs_sw_is_dirty;
    vmcs_clone->vmcs_base->vmcs_get_owner = vmcs_sw_get_owner;
    vmcs_clone->vmcs_base->vmcs_flush_to_memory = vmcs_0_flush_to_memory;
    vmcs_clone->vmcs_base->vmcs_destroy = vmcs_0_destroy;

    vmcs_clone->vmcs_base->vmcs_add_msr_to_vmexit_store_list = vmcs_sw_add_msr_to_vmexit_store_list;
    vmcs_clone->vmcs_base->vmcs_add_msr_to_vmexit_load_list = vmcs_sw_add_msr_to_vmexit_load_list;
    vmcs_clone->vmcs_base->vmcs_add_msr_to_vmenter_load_list = vmcs_sw_add_msr_to_vmexit_load_list;
    vmcs_clone->vmcs_base->vmcs_add_msr_to_vmexit_store_and_vmenter_load_list  = vmcs_sw_add_msr_to_vmexit_store_and_vmenter_load_lists;

    vmcs_clone->vmcs_base->vmcs_delete_msr_from_vmexit_store_list = vmcs_sw_delete_msr_from_vmexit_store_list;
    vmcs_clone->vmcs_base->vmcs_delete_msr_from_vmexit_load_list = vmcs_sw_delete_msr_from_vmexit_load_list;
    vmcs_clone->vmcs_base->vmcs_delete_msr_from_vmenter_load_list = vmcs_sw_delete_msr_from_vmenter_load_list;
    vmcs_clone->vmcs_base->vmcs_delete_msr_from_vmexit_store_and_vmenter_load_list  = vmcs_sw_delete_msr_from_vmexit_store_and_vmenter_load_lists;

    vmcs_clone->vmcs_base->level                  = VMCS_LEVEL_0;
    vmcs_clone->vmcs_base->skip_access_checking   = FALSE;
    vmcs_clone->vmcs_base->signature              = VMCS_SIGNATURE;

    vmcs_init_all_msr_lists(vmcs_clone->vmcs_base);

    // copy all fields as is
    for (field_id = (VMCS_FIELD)0; field_id < VMCS_FIELD_COUNT; (VMCS_FIELD)++field_id) {
        if (vmcs_field_is_supported(field_id)) {
            UINT64 value = vmcs_read(vmcs_origin, field_id);
            vmcs_write_nocheck(vmcs_clone->vmcs_base, field_id, value);
        }
    }

    /* Copy host bitmaps into newly created VMCS#0.
    *  Host HPA must be translated to HVA
    */
    vmcs_copy_extra_buffer(io_a_page, vmcs_origin, VMCS_IO_BITMAP_ADDRESS_A, PAGE_4KB_SIZE);
    vmcs_copy_extra_buffer(io_b_page, vmcs_origin, VMCS_IO_BITMAP_ADDRESS_B, PAGE_4KB_SIZE);
    vmcs_copy_extra_buffer(msr_page, vmcs_origin, VMCS_MSR_BITMAP_ADDRESS, PAGE_4KB_SIZE);

    // TODO: Copy MSR lists
    //vmcs_copy_extra_buffer(msr_vmexit_load_page, vmcs_origin, VMCS_EXIT_MSR_STORE_ADDRESS, 2*PAGE_4KB_SIZE);
    //vmcs_copy_extra_buffer(msr_vmexit_store_page, vmcs_origin, VMCS_EXIT_MSR_LOAD_ADDRESS, 2*PAGE_4KB_SIZE);
    //vmcs_copy_extra_buffer(msr_vmenter_load_page, vmcs_origin, VMCS_ENTER_MSR_LOAD_ADDRESS, 2*PAGE_4KB_SIZE);


    // Take all MSR lists from merged
    VMM_ASSERT(vmcs_origin->level == VMCS_MERGED);// Assuming that creation is from merged vmcs

    vmcs_0_take_msr_list_from_merged(vmcs_clone, vmcs_origin, VMCS_EXIT_MSR_STORE_ADDRESS, VMCS_EXIT_MSR_STORE_COUNT);
    vmcs_0_take_msr_list_from_merged(vmcs_clone, vmcs_origin, VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT);
    vmcs_0_take_msr_list_from_merged(vmcs_clone, vmcs_origin, VMCS_ENTER_MSR_LOAD_ADDRESS, VMCS_ENTER_MSR_LOAD_COUNT);

    vmcs_init_all_msr_lists(vmcs_origin);

    VMM_ASSERT(vmcs_get_owner(vmcs_origin) != NULL);

    // Fill anew MSR lists for merged vmcs
    vmcs_0_copy_msr_list_to_merged(vmcs_origin, vmcs_clone, VMCS_EXIT_MSR_STORE_ADDRESS, VMCS_EXIT_MSR_STORE_COUNT, vmcs_add_msr_to_vmexit_store_list);
    vmcs_0_copy_msr_list_to_merged(vmcs_origin, vmcs_clone, VMCS_EXIT_MSR_LOAD_ADDRESS, VMCS_EXIT_MSR_LOAD_COUNT, vmcs_add_msr_to_vmexit_load_list);
    vmcs_0_copy_msr_list_to_merged(vmcs_origin, vmcs_clone, VMCS_ENTER_MSR_LOAD_ADDRESS, VMCS_ENTER_MSR_LOAD_COUNT, vmcs_add_msr_to_vmenter_load_list);


    /* update extra pages, which are different for vmcs-0.
    * translation HVA->HPA is not necessary, since
    * these pages are never applied to hardware.
    */
    vmcs_write(vmcs_clone->vmcs_base, VMCS_IO_BITMAP_ADDRESS_A,    (UINT64) io_a_page);
    vmcs_write(vmcs_clone->vmcs_base, VMCS_IO_BITMAP_ADDRESS_B,    (UINT64) io_b_page);
    vmcs_write(vmcs_clone->vmcs_base, VMCS_MSR_BITMAP_ADDRESS,     (UINT64) msr_page);

    return vmcs_clone->vmcs_base;
}


void vmcs_copy_extra_buffer( void *dst, const struct _VMCS_OBJECT *vmcs_src,
                             VMCS_FIELD field, UINT32 bytes_to_copy)
{
    ADDRESS hpa, hva;

    hpa = vmcs_read(vmcs_src, field);
    if (TRUE == hmm_hpa_to_hva(hpa, &hva)) {
        vmm_memcpy(dst, (void *) hva, bytes_to_copy);
    }
    else {
        vmm_memset(dst, 0, PAGE_4KB_SIZE);
    }
}


void vmcs_0_destroy(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    void *page;

    VMM_ASSERT(p_vmcs);

    page = (void *) vmcs_read(vmcs, VMCS_IO_BITMAP_ADDRESS_A);
    if (NULL != page) vmm_page_free(page);
    page = (void *) vmcs_read(vmcs, VMCS_IO_BITMAP_ADDRESS_B);
    if (NULL != page) vmm_page_free(page);
    page = (void *) vmcs_read(vmcs, VMCS_MSR_BITMAP_ADDRESS);
    if (NULL != page) vmm_page_free(page);
    vmcs_destroy_all_msr_lists_internal(vmcs, FALSE);
    cache64_destroy(p_vmcs->cache);
}


void vmcs_0_flush_to_memory(struct _VMCS_OBJECT *vmcs)
{
    VMM_ASSERT(vmcs);
}


struct _VMCS_OBJECT * vmcs_1_create(GUEST_CPU_HANDLE gcpu, ADDRESS gpa)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs;
    ADDRESS hva;
    BOOLEAN status;
    GUEST_HANDLE guest;

    VMM_ASSERT(gcpu);

    guest = gcpu_guest_handle(gcpu);
    VMM_ASSERT(guest);

    if (0 != gpa) {  // gpa==0 means that VMCS-1 creation was requested for emulated guest
        // validate alignment
        if (0 != (gpa & PAGE_4KB_MASK)) {
            VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: GPA is NOT 4K aligned\n", __FUNCTION__);
            return NULL;
        }
        // map to host address space
        status = gpm_gpa_to_hva(gcpu_get_current_gpm(guest), gpa, &hva);

        if (TRUE != status) {
            VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Failed to translate GPA to HVA\n", __FUNCTION__);
            return NULL;
        }
        // check memory type TBD
    }

    p_vmcs = vmm_malloc(sizeof(*p_vmcs));
    if (NULL == p_vmcs) {
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }

    p_vmcs->cache = cache64_create(VMCS_FIELD_COUNT);
    if (NULL == p_vmcs->cache) {
        vmm_mfree(p_vmcs);
        VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Allocation failed\n", __FUNCTION__);
        return NULL;
    }

    p_vmcs->gcpu = gcpu;
    p_vmcs->gpa  = gpa;

    p_vmcs->vmcs_base->vmcs_read = vmcs_sw_read;
    p_vmcs->vmcs_base->vmcs_write = vmcs_sw_write;
    p_vmcs->vmcs_base->vmcs_flush_to_cpu = vmcs_sw_flush_to_cpu;
    p_vmcs->vmcs_base->vmcs_is_dirty = vmcs_sw_is_dirty;
    p_vmcs->vmcs_base->vmcs_get_owner = vmcs_sw_get_owner;
    p_vmcs->vmcs_base->vmcs_flush_to_memory   = vmcs_1_flush_to_memory;
    p_vmcs->vmcs_base->vmcs_destroy           = vmcs_1_destroy;
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmexit_store_list = NULL; // should not be used for level1
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmexit_load_list = NULL; // should not be used for level1
    p_vmcs->vmcs_base->vmcs_add_msr_to_vmenter_load_list = NULL; // should not be used for level1
    p_vmcs->vmcs_base->level                  = VMCS_LEVEL_1;
    p_vmcs->vmcs_base->skip_access_checking   = TRUE;
    p_vmcs->vmcs_base->signature              = VMCS_SIGNATURE;

    vmcs_init_all_msr_lists(p_vmcs->vmcs_base);

    return p_vmcs->vmcs_base;
}


void vmcs_1_destroy(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    vmcs_1_flush_to_memory(vmcs);
    cache64_destroy(p_vmcs->cache);
    // return VMCS page to the guest. TBD
}

void vmcs_1_flush_to_memory(struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;

    VMM_ASSERT(p_vmcs);

    do {    // do only once
        GUEST_HANDLE guest;
        ADDRESS      hva;
        BOOLEAN      status;

        if (0 == p_vmcs->gpa) {
            break;  // nothing to do. It's an emulated guest
        }

        if (NULL == p_vmcs->gcpu) {
            VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: GCPU is NULL\n", __FUNCTION__);
	    VMM_ASSERT(p_vmcs->gcpu);
            break;
        }

        guest = gcpu_guest_handle(p_vmcs->gcpu);
        if (NULL == guest) {
            VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Guest is NULL\n", __FUNCTION__);
	    VMM_ASSERT(guest);
            break;
        }

        status = gpm_gpa_to_hva(gcpu_get_current_gpm(guest), p_vmcs->gpa, &hva);

        VMM_ASSERT(TRUE == status);
        VMM_ASSERT(p_vmcs->gpa & PAGE_4KB_MASK);

        // check memory type TBD
        if (TRUE == status && 0 == (p_vmcs->gpa & PAGE_4KB_MASK)) {
            cache64_flush_to_memory(p_vmcs->cache, (void *)hva, PAGE_4KB_SIZE);
        }
        else {
            VMM_LOG(mask_anonymous, level_trace,"[vmcs] %s: Failed to map GPA to HVA\n", __FUNCTION__);
        }

    } while (0);

}


void vmcs_sw_write(struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id, UINT64 value)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    cache64_write(p_vmcs->cache, value, (UINT32 )field_id);
}


UINT64 vmcs_sw_read(const struct _VMCS_OBJECT *vmcs, VMCS_FIELD field_id)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    UINT64 value;
    VMM_ASSERT(p_vmcs);
    if (FALSE == cache64_read(p_vmcs->cache, &value, (UINT32 )field_id)) {
        value = 0;
    }
    return value;
}


void vmcs_sw_flush_to_cpu(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    cache64_flush_dirty(p_vmcs->cache, VMCS_FIELD_COUNT, NULL, NULL);    // just clean dirty bits
}


BOOLEAN vmcs_sw_is_dirty(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    return cache64_is_dirty(p_vmcs->cache);
}


GUEST_CPU_HANDLE vmcs_sw_get_owner(const struct _VMCS_OBJECT *vmcs)
{
    struct _VMCS_SOFTWARE_OBJECT *p_vmcs = (struct _VMCS_SOFTWARE_OBJECT *) vmcs;
    VMM_ASSERT(p_vmcs);
    return p_vmcs->gcpu;
}

static void vmcs_sw_add_msr_to_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, 
                                                UINT64 value)
{
    vmcs_add_msr_to_vmexit_store_list_internal(vmcs, msr_index, value, FALSE);
}

static void vmcs_sw_add_msr_to_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, 
                                                UINT64 value)
{
    vmcs_add_msr_to_vmexit_load_list_internal(vmcs, msr_index, value, FALSE);
}

#if 0 // Not currently used.
static void vmcs_sw_add_msr_to_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index, 
                                                UINT64 value)
{
    vmcs_add_msr_to_vmenter_load_list_internal(vmcs, msr_index, value, FALSE);
}
#endif

static void vmcs_sw_add_msr_to_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, 
                                                UINT32 msr_index, UINT64 value)
{
    vmcs_add_msr_to_vmexit_store_and_vmenter_load_lists_internal(vmcs, msr_index, value, FALSE);
}

static void vmcs_sw_delete_msr_from_vmexit_store_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_store_list_internal(vmcs, msr_index, FALSE);
}

static void vmcs_sw_delete_msr_from_vmexit_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_load_list_internal(vmcs, msr_index, FALSE);
}

static void vmcs_sw_delete_msr_from_vmenter_load_list(struct _VMCS_OBJECT *vmcs, UINT32 msr_index)
{
    vmcs_delete_msr_from_vmenter_load_list_internal(vmcs, msr_index, FALSE);
}

static void vmcs_sw_delete_msr_from_vmexit_store_and_vmenter_load_lists(struct _VMCS_OBJECT *vmcs, UINT32 msr_index)
{
    vmcs_delete_msr_from_vmexit_store_and_vmenter_load_lists_internal(vmcs, msr_index, FALSE);
}

