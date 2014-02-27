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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMX_TEARDOWN_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMX_TEARDOWN_C, __condition)
#include "lock.h"
#include "vmx_teardown.h"
#include "hw_utils.h"
#include "guest_cpu.h"
#include "vmm_callback.h"

/*
 * Following defintions are based on uVMM operated in 64 bits PAE mode
 */

#define VMAM_PAE_NUM_OF_TABLE_ENTRIES 512
#define VMAM_PAE_ENTRY_INCREMENT 8
#define VMAM_PML4TE_INDEX_MASK (UINT64)0x0000FF8000000000
#define VMAM_PML4TE_INDEX_SHIFT 39
#define VMAM_PDPTE_INDEX_MASK (UINT64)0x0000007FC0000000
#define VMAM_PDPTE_INDEX_SHIFT  30
#define VMAM_PDE_INDEX_MASK 0x3FE00000
#define VMAM_PDE_INDEX_SHIFT 21
#define VMAM_PTE_INDEX_MASK  0x1FF000
#define VMAM_PTE_INDEX_SHIFT  12
#define VMAM_PDPT_ALIGNMENT 32
#define VMAM_LOW_ADDR_SHIFT 12
#define VMAM_LOW_ADDR_MASK 0xFFFFF
#define VMAM_HIGH_ADDR_SHIFT 32
#define VMAM_HIGH_ADDR_MASK 0xFFFFF
#define VMAM_PAGE_BOUNDARY_MASK 0xFFFFFFFFFFFFF000

typedef union VMAM_PAE_LME_ENTRY_U {
        struct {
                UINT32
                        present        :1,  /* 0=not present, 1=present */
                        writable       :1,  /* 0=read-only, 1=read-writable */
                        user           :1,  /* 0=supervisor-only, 1=user+supervisor */
                        pwt            :1,
                        pcd            :1,
                        accessed       :1,
                        dirty          :1,
                        page_size      :1,  /* page size, in last level entry */
                        global         :1,
                        available      :3,
                        addr_base_low  :20; /* bit 31:12 of the physical address of next level enty */ 
                UINT32
                        addr_base_high :20, /* bit 51:32 of the physical address of next level enty */
                    avl_or_res     :11,
            exb_or_res     :1;  /* execution disable */
        } bits;
        UINT64 raw;                             /* whole entry */
} VMAM_PAE_LME_ENTRY;

///---- globals ---- //

// should be assigned during the initializtion stage.
UINT64  g_session_id = 0;

static
void read_vmcs_to_get_guest_states(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_GUEST_STATES *guest_states);

static BOOLEAN is_params_ok(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *p, UINT64 *state_hva);
static BOOLEAN map_thunk_pages(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *teardown);

///---- static functions ---- //
static 
UINT64 vmam_get_pml4_base_from_cr3(UINT64 cr3);
 
static
BOOLEAN vmam_hpa_to_hva(IN UINT64 hpa, OUT UINT64* hva);


static
BOOLEAN vmam_hva_to_hpa(IN UINT64 hva, OUT UINT64* hpa);

static
void vmam_get_indices(IN UINT64 virtual_address, OUT UINT32* pml4te_index,
                      OUT UINT32* pdpte_index, OUT UINT32* pde_index,
                      OUT UINT32* pte_index);

static
VMAM_PAE_LME_ENTRY* vmam_get_table_entry_ptr(UINT64 table_hpa, UINT32 entry_index);
 
static
void vmam_get_entry_val(VMAM_PAE_LME_ENTRY* pentry_val, VMAM_PAE_LME_ENTRY* pentry);

static
UINT64 vmam_get_phys_addr(IN VMAM_PAE_LME_ENTRY* pentry);

static
void vmam_set_table_entry(IN VMAM_PAE_LME_ENTRY* pentry, IN UINT64 entry_hpa);

static
UINT64 vmam_create_pdpt_to_pt(IN UINT32 pdpte_index, IN UINT32 pde_index, 
                              IN UINT32 pte_index, IN UINT64 start_hpa);

static
UINT64 vmam_create_pdt_to_pt(IN UINT32 pde_index, IN UINT32 pte_index,
                             IN UINT64 start_hpa);
                                             
static
UINT64 vmam_create_pt(IN UINT32 pte_index, IN UINT64 start_hpa);

static 
BOOLEAN vmam_check_add_one_page_mem_map(IN UINT64 host_cr3, IN UINT64 host_cr4,
                                        IN UINT64 efer_value, IN UINT64 start_hva,
                                        IN UINT64 start_hpa);

// ---- externs ---- //
extern void ITP_JMP_DEADLOOP(void);

BOOLEAN vmexit_vmm_teardown(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *vmm_teardown_params)
{
    VMM_TEARDOWN_GUEST_STATES* vm_guest_states = NULL;
    UINT64 state_hva = 0;
    REPORT_VMM_TEARDOWN_DATA vmm_teardown_data;

    UINT32 cpu_idx = hw_cpu_id();

    vmm_teardown_data.nonce = vmm_teardown_params->nonce;

    if (!is_params_ok(gcpu, vmm_teardown_params, &state_hva) ||
        !report_uvmm_event(UVMM_EVENT_VMM_TEARDOWN, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), (void *)&vmm_teardown_data)) {
        return FALSE;
    }

    vm_guest_states = (VMM_TEARDOWN_GUEST_STATES *)state_hva;

    // disable vtd
#ifdef ENABLE_VTD
        vtd_deinitialize();
#endif
        // get the guest states from vmcs and save them 
        read_vmcs_to_get_guest_states(gcpu, vm_guest_states);

    if(vmm_teardown_params->is_guest_x64_mode == 1){
        EM64T_GDTR *gdtr = NULL;
                EM64T_IDT_DESCRIPTOR *idtr = NULL;

                gdtr = (EM64T_GDTR *) (&(vm_guest_states->GUEST_GDTR_LO));
                // update gdtr contents
        gdtr->limit = (UINT16)(vm_guest_states->IA32_GDTR_LIMIT);
        gdtr->base  = (UINT64)(vm_guest_states->IA32_GDTR_BASE);
                VMM_LOG(mask_anonymous, level_trace,"vmcall_teardown_64bits: gdtr->limit = %p, gdtr->base = %p\r\n", gdtr->limit, gdtr->base);

                idtr = (EM64T_IDT_DESCRIPTOR *) (&(vm_guest_states->GUEST_IDTR_LO));
                // update idtr contents
        idtr->limit = (UINT16)(vm_guest_states->IA32_IDTR_LIMIT);
        idtr->base  = (UINT64)(vm_guest_states->IA32_IDTR_BASE);
                VMM_LOG(mask_anonymous, level_trace,"vmcall_teardown_64bits: idtr->limit = %p, idtr->base = %p\r\n", idtr->limit, idtr->base);

        if (!map_thunk_pages(gcpu, vmm_teardown_params)) {
            return FALSE;
        }

                // restore the guest states and jump to teardown thunk. 
            // never returns
        call_teardown_thunk64( cpu_idx, vmm_teardown_params->guest_states_storage_virt_addr,
            vm_guest_states->ADDR_OF_TEARDOWN_THUNK);
    }
    else if(vmm_teardown_params->is_guest_x64_mode == 0){
        IA32_GDTR *gdtr = NULL;
        IA32_IDTR *idtr = NULL;
        BOOLEAN cr4_pae_is_on = FALSE;

        /* Boolean cr4_pae_is_on is obtained from guest CR4. This is
         * required to determine if PAE needs to be turned on or not inside
         * call_teardown_thunk32() method below. */
        cr4_pae_is_on = BIT_GET64(
                   gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4), 5);

        gdtr = (IA32_GDTR *) (&(vm_guest_states->GUEST_GDTR_LO));

        // update gdtr contents
        gdtr->limit = (UINT16)(vm_guest_states->IA32_GDTR_LIMIT);
        gdtr->base  = (UINT32)(vm_guest_states->IA32_GDTR_BASE);
                VMM_LOG(mask_anonymous, level_trace, "vmcall_teardown_32bits: gdtr->limit = %p, gdtr->base = %p\r\n", gdtr->limit, gdtr->base);

                idtr = (IA32_IDTR *) (&(vm_guest_states->GUEST_IDTR_LO));
                // update idtr contents
        idtr->limit = (UINT16)(vm_guest_states->IA32_IDTR_LIMIT);
        idtr->base  = (UINT32)(vm_guest_states->IA32_IDTR_BASE);
                VMM_LOG(mask_anonymous, level_trace, "vmcall_teardown_32bits: idtr->limit = %p, idtr->base = %p\r\n", idtr->limit, idtr->base);

        // restore the guest states and jump to teardown thunk. 
        // never returns
        call_teardown_thunk32( vmm_teardown_params->guest_states_storage_virt_addr,
                COMPATIBILITY_CODE32_CS /*vmm_compat_cs*/,
                vm_guest_states->ADDR_OF_TEARDOWN_THUNK,
                vmm_teardown_params->cr3_td_sm_32, cr4_pae_is_on);
    }
    else{
        VMM_LOG(mask_anonymous, level_error,"%%s (line %d): Error - teardown feature is not implemented in unknown processor mode\n", __FUNCTION__, __LINE__);
        return FALSE;
    }
    return TRUE;
}

/*
 * copy current vmm cs entry in vmm gdt to guest cs entry in vmm gdt
 */
static
void read_vmcs_to_get_guest_states(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_GUEST_STATES *guest_states)
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    VM_ENTRY_CONTROLS vmentry_control;
    
    VMM_ASSERT(vmcs);

    if(!guest_states)
        return;

    vmentry_control.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_ENTER_CONTROL_VECTOR);

    // get gp registers;
    guest_states->IA32_GP_RAX = gcpu_get_gp_reg(gcpu, IA32_REG_RAX);
    guest_states->IA32_GP_RBX = gcpu_get_gp_reg(gcpu, IA32_REG_RBX);
    guest_states->IA32_GP_RCX = gcpu_get_gp_reg(gcpu, IA32_REG_RCX);
    guest_states->IA32_GP_RDX = gcpu_get_gp_reg(gcpu, IA32_REG_RDX);
    guest_states->IA32_GP_RDI = gcpu_get_gp_reg(gcpu, IA32_REG_RDI);
    guest_states->IA32_GP_RSI = gcpu_get_gp_reg(gcpu, IA32_REG_RSI);
    guest_states->IA32_GP_RBP = gcpu_get_gp_reg(gcpu, IA32_REG_RBP);
    guest_states->IA32_GP_RSP = gcpu_get_gp_reg(gcpu, IA32_REG_RSP);
    guest_states->IA32_GP_R8  = gcpu_get_gp_reg(gcpu, IA32_REG_R8);
    guest_states->IA32_GP_R9  = gcpu_get_gp_reg(gcpu, IA32_REG_R9);
    guest_states->IA32_GP_R10 = gcpu_get_gp_reg(gcpu, IA32_REG_R10);
    guest_states->IA32_GP_R11 = gcpu_get_gp_reg(gcpu, IA32_REG_R11);
    guest_states->IA32_GP_R12 = gcpu_get_gp_reg(gcpu, IA32_REG_R12);
    guest_states->IA32_GP_R13 = gcpu_get_gp_reg(gcpu, IA32_REG_R13);
    guest_states->IA32_GP_R14 = gcpu_get_gp_reg(gcpu, IA32_REG_R14);
    guest_states->IA32_GP_R15 = gcpu_get_gp_reg(gcpu, IA32_REG_R15);

    guest_states->IA32_REG_RIP     = gcpu_get_gp_reg(gcpu, IA32_REG_RIP);
    guest_states->IA32_INSTR_LENTH = vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    guest_states->IA32_REG_RFLAGS  = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);

    // control registers
    guest_states->IA32_CR0 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
    guest_states->IA32_CR3 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR3);
    guest_states->IA32_CR4 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4);
    guest_states->IA32_CR8 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR8);
    

    // segment registers
    guest_states->IA32_ES_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_ES_SELECTOR); 
    guest_states->IA32_CS_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_CS_SELECTOR); 
    guest_states->IA32_SS_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_SS_SELECTOR);
    guest_states->IA32_DS_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_DS_SELECTOR);
    guest_states->IA32_FS_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_FS_SELECTOR);
        guest_states->IA32_GS_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_GS_SELECTOR);
    guest_states->IA32_LDTR_SELECTOR = vmcs_read(vmcs, VMCS_GUEST_LDTR_SELECTOR);    
        guest_states->IA32_TR_SELECTOR   = vmcs_read(vmcs, VMCS_GUEST_TR_SELECTOR);

    // gdtr/ldtr
    guest_states->IA32_GDTR_BASE     = vmcs_read(vmcs, VMCS_GUEST_GDTR_BASE);
    guest_states->IA32_GDTR_LIMIT    = vmcs_read(vmcs, VMCS_GUEST_GDTR_LIMIT);
    guest_states->IA32_IDTR_BASE     = vmcs_read(vmcs, VMCS_GUEST_IDTR_BASE);
    guest_states->IA32_IDTR_LIMIT    = vmcs_read(vmcs, VMCS_GUEST_IDTR_LIMIT);

        // msrs

    guest_states->IA32_MSR_DEBUG_CTL = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_DEBUGCTL);
    if(vmentry_control.Bits.LoadDebugControls) {
        guest_states->IA32_DR7             = vmcs_read(vmcs, VMCS_GUEST_DR7);
    }
    else {
        //On VMEXIT hardware sets D47=0x400. If feature to save DR7 is not available, DR7
        guest_states->IA32_DR7             = 0x400;
    }

    guest_states->IA32_MSR_SYSENT_CS   = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_SYSENTER_CS);
    guest_states->IA32_MSR_SYSENT_ESP  = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_SYSENTER_ESP);
    guest_states->IA32_MSR_SYSENT_EIP  = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_SYSENTER_EIP);

    guest_states->IA32_MSR_PERF_GLB_CTL = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_PERF_GLOBAL_CTRL);
    guest_states->IA32_MSR_PAT_REG   = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_PAT);
    guest_states->IA32_MSR_EFER_REG  = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    
    // smbase
    guest_states->IA32_SMBASE            = vmcs_read(vmcs, VMCS_GUEST_SMBASE);      

    //fs_base and gs_base
    guest_states->IA32_FS_BASE           = vmcs_read(vmcs, VMCS_GUEST_FS_BASE);     
    guest_states->IA32_GS_BASE           = vmcs_read(vmcs, VMCS_GUEST_GS_BASE);
}

static BOOLEAN is_params_ok(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *p, UINT64 *state_hva)
{
    VMM_TEARDOWN_GUEST_STATES *state;
    UINT64 thunk_hva = 0;

    if(p->size_of_this_structure != sizeof(VMM_TEARDOWN_PARAMS)) {
        VMM_LOG(mask_anonymous, level_error, "%s: wrong params size!\n", __FUNCTION__);
        return FALSE;
    }

    if(p->session_id != g_session_id) {
        VMM_LOG(mask_anonymous, level_error, "%s: wrong session id!\n", __FUNCTION__);
        return FALSE;
    }

    if(!gcpu_gva_to_hva(gcpu, p->teardownthunk_gva, &thunk_hva) ||
       !gcpu_gva_to_hva(gcpu, p->guest_states_storage_virt_addr, state_hva)) {
        VMM_LOG(mask_anonymous, level_error, "%s: wrong thunk/state HVA!\n", __FUNCTION__);
        return FALSE;
    }

    state = (VMM_TEARDOWN_GUEST_STATES *)(*state_hva);

    if ((state == NULL) || (state->SIZE_OF_THIS_STRUCTURE != sizeof(VMM_TEARDOWN_GUEST_STATES))) {
        VMM_LOG(mask_anonymous, level_error, "%s: invalid guest state!\n", __FUNCTION__);
        return FALSE;
    }

    VMM_LOG( mask_anonymous, level_trace,
        "thunk gva (hva) = %llx (%llx), state = %llx (%llx), td cr3 = %llx\n",
        (UINT64)p->teardownthunk_gva, thunk_hva, (UINT64)p->guest_states_storage_virt_addr,
        *state_hva, (UINT64)p->cr3_td_sm_32);

    return TRUE;
}

static VMM_LOCK teardown_lock = LOCK_INIT_STATE;
static int teardown_mapped = 0;
static int teardown_failed = 0;

void init_teardown_lock(void)
{
    lock_initialize(&teardown_lock);
}

/*
 * Logic
 *      mapped      failed      to-do
 *          0           0       start mapping buffer
 *          0           1       return failure
 *          1           0       return success
 *          1           1       return failure
 */

static BOOLEAN map_thunk_pages(GUEST_CPU_HANDLE gcpu, VMM_TEARDOWN_PARAMS *p)
{
    BOOLEAN ret = FALSE;
    UINT64 tmp;

    lock_acquire(&teardown_lock);

    if ((teardown_mapped != 0) || (teardown_failed != 0)) {
        ret = (teardown_failed == 0) ? TRUE : FALSE;
        goto clean_up;
    }

    ret = vmam_add_to_host_page_table( gcpu, p->teardownthunk_gva, 1);

    if (!ret) {
        teardown_failed = 1;
        goto clean_up;
    }

    ret = vmam_add_to_host_page_table( gcpu, p->teardown_buffer_gva,
                      p->teardown_buffer_size / PAGE_4KB_SIZE);

    if (!ret) {
        teardown_failed = 1;
        goto clean_up;
    }
    teardown_mapped = 1;

clean_up:

    tmp = 0;
    hw_invlpg((void *)(p->teardownthunk_gva));

    while (tmp < p->teardown_buffer_size) {
        hw_invlpg((void *)(p->teardown_buffer_gva + tmp));
        tmp += PAGE_4KB_SIZE;
    }
    lock_release(&teardown_lock);
    return ret;
}

static 
UINT64 vmam_get_pml4_base_from_cr3(UINT64 cr3) {
    return ALIGN_BACKWARD(cr3, VMAM_PDPT_ALIGNMENT);
}

static
BOOLEAN vmam_hpa_to_hva(IN UINT64 hpa, OUT UINT64* hva) {
    return (hmm_hpa_to_hva(hpa, hva));
}

static
BOOLEAN vmam_hva_to_hpa(IN UINT64 hva, OUT UINT64* hpa) {
    return (hmm_hva_to_hpa(hva, hpa));
}

static
void vmam_get_indices(IN UINT64 virtual_address,
                      OUT UINT32* pml4te_index,
                      OUT UINT32* pdpte_index,
                      OUT UINT32* pde_index,
                      OUT UINT32* pte_index) {

    UINT32 virtual_address_low_32_bit = (UINT32)virtual_address;

        UINT64 pml4te_index_tmp = ((virtual_address & VMAM_PML4TE_INDEX_MASK) >> VMAM_PML4TE_INDEX_SHIFT);
    UINT64 pdpte_index_tmp = ((virtual_address & VMAM_PDPTE_INDEX_MASK) >> VMAM_PDPTE_INDEX_SHIFT);

    *pml4te_index = (UINT32)pml4te_index_tmp;
    *pdpte_index = (UINT32)pdpte_index_tmp;
    *pde_index = ((virtual_address_low_32_bit & VMAM_PDE_INDEX_MASK) >> VMAM_PDE_INDEX_SHIFT);
    VMM_ASSERT(*pde_index < VMAM_PAE_NUM_OF_TABLE_ENTRIES);
    *pte_index = ((virtual_address_low_32_bit & VMAM_PTE_INDEX_MASK) >> VMAM_PTE_INDEX_SHIFT);
    VMM_ASSERT(*pte_index < VMAM_PAE_NUM_OF_TABLE_ENTRIES);
}

static
VMAM_PAE_LME_ENTRY* vmam_get_table_entry_ptr(UINT64 table_hpa,
                                                                                     UINT32 entry_index) {
    UINT64 entry_hpa;
    UINT64 entry_hva;

    entry_hpa = table_hpa + entry_index * VMAM_PAE_ENTRY_INCREMENT;
    
     if (!vmam_hpa_to_hva(entry_hpa, &entry_hva)) {
        return NULL;
    }
    return (VMAM_PAE_LME_ENTRY*)entry_hva;
}
 
static
void vmam_get_entry_val(VMAM_PAE_LME_ENTRY* pentry_val,
                                                VMAM_PAE_LME_ENTRY* pentry) {

    volatile UINT64* origl_val_ptr = (volatile UINT64*)pentry;
    UINT64 value1 = *origl_val_ptr;
    UINT64 value2 = *origl_val_ptr;

    while (value1 != value2) {
        value1 = value2;
        value2 = *origl_val_ptr;
    }

    *pentry_val = *((VMAM_PAE_LME_ENTRY*)(&value1));
}

static
UINT64 vmam_get_phys_addr(IN VMAM_PAE_LME_ENTRY* pentry) {
        UINT32 addr_low = pentry->bits.addr_base_low << VMAM_LOW_ADDR_SHIFT;
    UINT32 addr_high = pentry->bits.addr_base_high;
    return ((UINT64)addr_high << VMAM_HIGH_ADDR_SHIFT) | addr_low;
}

static
void vmam_set_table_entry(IN VMAM_PAE_LME_ENTRY* pentry,
                                                  IN UINT64 entry_hpa) {
    VMAM_PAE_LME_ENTRY entry_val;
    
    entry_val.raw =0;   
    entry_val.bits.present = 1;
    entry_val.bits.writable = 1;
    entry_val.bits.addr_base_low = (UINT32)((entry_hpa >> VMAM_LOW_ADDR_SHIFT) & VMAM_LOW_ADDR_MASK);
    entry_val.bits.addr_base_high = (UINT32)((entry_hpa >> VMAM_HIGH_ADDR_SHIFT) & VMAM_HIGH_ADDR_MASK);        
        *pentry =  entry_val;
        VMM_LOG(mask_anonymous, level_trace, "%s: table entry at 0x%llx set to 0x%llx\n", __FUNCTION__, (UINT64)pentry, entry_val.raw);
}

static
UINT64 vmam_create_pdpt_to_pt(IN UINT32 pdpte_index, IN UINT32 pde_index, 
                              IN UINT32 pte_index, IN UINT64 start_hpa) {                              
    UINT64 pdpt_base_hva = (UINT64)(vmm_memory_alloc(2 * PAGE_4KB_SIZE - 1)); 
    UINT64 pdpt_base_hpa;                             
    VMAM_PAE_LME_ENTRY* pdpte_ptr = NULL;
    UINT64 pdt_hpa;
    
    if(!pdpt_base_hva) {
                VMM_LOG(mask_anonymous, level_error,"%s (line %d): allocation of memory for pdpt failed !\n", __FUNCTION__, __LINE__);
                VMM_DEADLOOP();
    }

    pdpt_base_hva = pdpt_base_hva & VMAM_PAGE_BOUNDARY_MASK;  /* aligned to page boundary */
    if (!vmam_hva_to_hpa(pdpt_base_hva, &pdpt_base_hpa)) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): conversion of pdpt_base_hva to pdpt_base_hpa failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
    pdt_hpa = vmam_create_pdt_to_pt(pde_index, pte_index, start_hpa);
    if (!pdt_hpa) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): vmam_create_pdt_to_pt failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }       
    pdpte_ptr = (VMAM_PAE_LME_ENTRY*) (pdpt_base_hva + pdpte_index * VMAM_PAE_ENTRY_INCREMENT);
    vmam_set_table_entry(pdpte_ptr, pdt_hpa);
    return pdpt_base_hpa;
}         

static
UINT64 vmam_create_pdt_to_pt(IN UINT32 pde_index, IN UINT32 pte_index,
                                             IN UINT64 start_hpa) {    
    UINT64 pdt_base_hva = (UINT64)(vmm_memory_alloc(2 * PAGE_4KB_SIZE - 1));
    UINT64 pdt_base_hpa;                              
    VMAM_PAE_LME_ENTRY* pdte_ptr = NULL;
    UINT64 pt_hpa;
    
    if(!pdt_base_hva) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): allocation of memory for pdt failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
    pdt_base_hva = pdt_base_hva & VMAM_PAGE_BOUNDARY_MASK;  /* aligned to page boundary */
    if (!vmam_hva_to_hpa(pdt_base_hva, &pdt_base_hpa)) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): conversion of pdt_base_hva to pdt_base_hpa failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
    pt_hpa = vmam_create_pt(pte_index, start_hpa);
    if (!pt_hpa) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): vmam_create_pt failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }       
    pdte_ptr = (VMAM_PAE_LME_ENTRY*) (pdt_base_hva + pde_index * VMAM_PAE_ENTRY_INCREMENT);
    vmam_set_table_entry(pdte_ptr, pt_hpa);
    return pdt_base_hpa;
}         

static
UINT64 vmam_create_pt(IN UINT32 pte_index, IN UINT64 start_hpa) {                              
    UINT64 pt_base_hva = (UINT64)(vmm_memory_alloc(2 * PAGE_4KB_SIZE - 1));
    UINT64 pt_base_hpa;
    VMAM_PAE_LME_ENTRY* pte_ptr = NULL;
    
    if(!pt_base_hva) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): allocation of memory for pt failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
    pt_base_hva = pt_base_hva & VMAM_PAGE_BOUNDARY_MASK;  /* aligned to page boundary */
    if (!vmam_hva_to_hpa(pt_base_hva, &pt_base_hpa)) {
        VMM_LOG(mask_anonymous, level_error,"%s (line %d): conversion of pt_base_hva to pt_base_hpa failed !\n", __FUNCTION__, __LINE__);
        VMM_DEADLOOP();
    }
    pte_ptr = (VMAM_PAE_LME_ENTRY*) (pt_base_hva + pte_index * VMAM_PAE_ENTRY_INCREMENT);
    vmam_set_table_entry(pte_ptr, start_hpa);
    return pt_base_hpa;
}         

static 
BOOLEAN vmam_check_add_one_page_mem_map(IN UINT64 host_cr3, IN UINT64 host_cr4,
                                        IN UINT64 efer_value, IN UINT64 start_hva, IN UINT64 start_hpa) {
    BOOLEAN is_lme = ((efer_value & EFER_LME) != 0);
    BOOLEAN is_pae = ((host_cr4 & CR4_PAE) != 0);
    UINT32 pml4te_index;
    UINT32 pdpte_index;
    UINT32 pde_index;
    UINT32 pte_index;
    UINT64 pml4t_base_hpa;
    VMAM_PAE_LME_ENTRY* pml4te_ptr = NULL;
    VMAM_PAE_LME_ENTRY pml4te_val;
    UINT64 pdpt_hpa;
    VMAM_PAE_LME_ENTRY* pdpte_ptr = NULL;
    VMAM_PAE_LME_ENTRY pdpte_val;
    UINT64 pdt_hpa;
    VMAM_PAE_LME_ENTRY* pdte_ptr = NULL;
    VMAM_PAE_LME_ENTRY pdte_val;
    UINT64 pt_hpa;
    UINT64 pg_hpa;
    VMAM_PAE_LME_ENTRY* pte_ptr = NULL;
    VMAM_PAE_LME_ENTRY pte_val;
    BOOLEAN result = TRUE;

    /* vmm runs in PAE and LME mode */
    if (!is_lme || !is_pae) {
        VMM_LOG(mask_anonymous, level_error, "%s (line %d): vmm should be in PAE and LME mode\n", __FUNCTION__, __LINE__); 
        VMM_DEADLOOP();
    }

    vmam_get_indices(start_hva, &pml4te_index, &pdpte_index, &pde_index, &pte_index);
    pml4t_base_hpa = vmam_get_pml4_base_from_cr3(host_cr3);
    pml4te_ptr = vmam_get_table_entry_ptr(pml4t_base_hpa, pml4te_index);
    if (pml4te_ptr == NULL) {
        VMM_LOG(mask_anonymous, level_error, "%s (line %d): pml4te_ptr is NULL\n", __FUNCTION__, __LINE__); 
        VMM_DEADLOOP();
    }

    vmam_get_entry_val(&pml4te_val, pml4te_ptr);
    if (!pml4te_val.bits.present) {
        pdpt_hpa = vmam_create_pdpt_to_pt(pdpte_index, pde_index, pte_index, start_hpa);
        if (!pdpt_hpa) {
            VMM_LOG(mask_anonymous, level_error, "%s (line %d): vmam_create_pdpt_to_pt failed !\n", __FUNCTION__, __LINE__);
                VMM_DEADLOOP();
        }
        vmam_set_table_entry(pml4te_ptr, pdpt_hpa);
        result = TRUE;
    } else { /* pml4te present case */
        pdpt_hpa = vmam_get_phys_addr(&pml4te_val);
        pdpte_ptr = vmam_get_table_entry_ptr(pdpt_hpa, pdpte_index);
        if (pdpte_ptr == NULL) {
            VMM_LOG(mask_anonymous, level_error, "%s (line %d): pdpte_ptr is NULL !\n", __FUNCTION__, __LINE__);
            VMM_DEADLOOP();
        }
        vmam_get_entry_val(&pdpte_val, pdpte_ptr);

        if (!pdpte_val.bits.present) { /* pde not present */
            pdt_hpa = vmam_create_pdt_to_pt(pde_index, pte_index, start_hpa);
            if (!pdt_hpa) {
                VMM_LOG(mask_anonymous, level_error, "%s (line %d): vmam_create_pdt_to_pt failed !\n", __FUNCTION__, __LINE__);
                VMM_DEADLOOP();
            }       
            vmam_set_table_entry(pdpte_ptr, pdt_hpa);
            result = TRUE;
        } else { /* pdpte present case */
            pdt_hpa = vmam_get_phys_addr(&pdpte_val); 
            pdte_ptr = vmam_get_table_entry_ptr(pdt_hpa, pde_index);
            if (pdte_ptr == NULL) {
                VMM_LOG(mask_anonymous, level_error, "%s (line %d): pdte_ptr is NULL\n", __FUNCTION__, __LINE__); 
                VMM_DEADLOOP();
            }
            vmam_get_entry_val(&pdte_val, pdte_ptr);

            if (!pdte_val.bits.present) { /* pt not present case */
                pt_hpa = vmam_create_pt(pte_index, start_hpa);
                if (!pt_hpa) {
                    VMM_LOG(mask_anonymous, level_error, "%s (line %d): vmam_create_pdt_to_pt failed !\n", __FUNCTION__, __LINE__);
                    VMM_DEADLOOP();
                }       
                vmam_set_table_entry(pdte_ptr, pt_hpa);
                result = TRUE;
            } else { /* pte present exist cas */
                pt_hpa = vmam_get_phys_addr(&pdte_val);
                pte_ptr = vmam_get_table_entry_ptr(pt_hpa, pte_index);
                if (pte_ptr == NULL) {
                    VMM_LOG(mask_anonymous, level_error, "%s (line %d): pte_ptr is NULL\n", __FUNCTION__, __LINE__); 
                    VMM_DEADLOOP();
                }
                vmam_get_entry_val(&pte_val, pte_ptr);
                if (!pte_val.bits.present) { /* pte not exist */
                    vmam_set_table_entry(pte_ptr, start_hpa);
                    result = TRUE;
                } else { /* pte existing */     
                    /* retrieve HPA of guest PT */
                    pg_hpa = vmam_get_phys_addr(&pte_val);
                    if (pg_hpa != start_hpa) { /* overwrite */
                        vmam_set_table_entry(pte_ptr, start_hpa);
                    result = TRUE;
                    } else {
                        VMM_LOG(mask_anonymous, level_trace, "%s: hpa == start_hpa found!\n", __FUNCTION__);
                        result = TRUE;                                          
                    }
                }
            }
        }
    }
    return result;
}

BOOLEAN vmam_add_to_host_page_table(IN GUEST_CPU_HANDLE gcpu, IN UINT64 start_gva,
    IN UINT64 num_pages) {

    UINT64 host_cr3 = hw_read_cr3();
    UINT64 host_cr4 = hw_read_cr4();
    UINT64 efer_value =  hw_read_msr(IA32_MSR_EFER);

    UINT32 i = 0;
    BOOLEAN result = TRUE;
    UINT64 gpa = 0;

    if (!gcpu_gva_to_gpa(gcpu, start_gva, &gpa))
        return FALSE;

    for(i=0; i < num_pages; i++) {
        result = vmam_check_add_one_page_mem_map( host_cr3, host_cr4,
                efer_value, start_gva + i * PAGE_4KB_SIZE, gpa + i * PAGE_4KB_SIZE);
        if(!result) {
            return result;
        }
    }
    return result;
}
