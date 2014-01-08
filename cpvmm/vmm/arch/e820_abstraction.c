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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(E820_ABSTRACTION_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(E820_ABSTRACTION_C, __condition)
#include <vmm_defs.h>
#include <vmm_arch_defs.h>
#include <e820_abstraction.h>
#include <heap.h>
#include <common_libc.h>
#include "vmm_dbg.h"
#ifdef ENABLE_INT15_VIRTUALIZATION
#include "vmm_objects.h"
#include "gpm_api.h"
#include "guest_cpu.h"
#include "guest.h"
#include "host_memory_manager_api.h"
#include "../guest/guest_cpu/unrestricted_guest.h"

UINT32 g_int15_trapped_page = 0;
UINT32 g_int15_orignal_vector = 0;
E820MAP_STATE 			*g_emap;
#endif // ENABLE_INT15_VIRTUALIZATION
/*------------------------------------------------------------*/

static INT15_E820_MEMORY_MAP* g_e820_map = NULL;

// static 
const char* g_int15_e820_type_name[] = {
    "UNKNOWN", // 0
    "MEMORY",  // 1
    "RESERVED",// 2
    "ACPI",    // 3
    "NVS",     // 4
    "UNUSABLE" // 5
};
#ifdef ENABLE_INT15_VIRTUALIZATION
static UINT8 int15_handler_code[] =
{
	0x3d,0x20,0xe8, 			// 			cmp ax, 0xe820
	0x74,0x05,	 				// 			jz Handler
	0xea,0x00,0x00,0x00,0x00, 	// 			jmp orig_handler
	0x0f,0x01,0xc1, 			// Handler: vmcall
	0xcf						// 				iret
};
								// conditional jump can be only
								// near jump, hence too jumps in
								// this assembly code
#endif // ENABLE_INT15_VIRTUALIZATION
#define E820_NAMES_COUNT (sizeof(g_int15_e820_type_name)/sizeof(const char*))

#ifdef ENABLE_INT15_VIRTUALIZATION
/*------------------------------------------------------------*/

/*
 * This function is supposed to setup int15 handling
 * it will write its own handling code to vector area which is
 * not being used or known to not being used. So we only
 * handle E820 type INT15 interrupt, any other type of
 * INT15 will be handled by the original vector.
 */
void update_int15_handling(void)
{

	UINT32 int15_vector, i;
	UINT32 *int15_vector_offset = (UINT32*)((UINT64)INT15_VECTOR_LOCATION);

	// save original vector location to use in vmexit
	g_int15_orignal_vector = *(int15_vector_offset);

	int15_vector = INT15_HANDLER_ADDR; //use some location in INT vector table which is not being used

	g_int15_trapped_page = int15_vector; //CS:IP format vector
	*(int15_vector_offset) = g_int15_trapped_page; //hookup our INT15 vector(seg:offset)

	//patch the original vector
	*(UINT32*)&int15_handler_code[ORIG_HANDLER_OFFSET] = g_int15_orignal_vector;

	//put out warning if the vector area is being used
	// vectors we are using are user defined, it is possible
	// some user might decide to use. Nothing we could do about
	// but would like to through some indication that those vectors
	// were non-zero
	for (i=0; i<sizeof(int15_handler_code); i=i+4)	{
		if (*(UINT32*)(UINT64)(int15_vector+i) != 0)
			VMM_LOG(mask_anonymous, level_error, "WARNING: User defined Interrupts being over written (0x%x)\n",*(UINT32*)(UINT64)(int15_vector+i) );
	}

	//write patched code to the interrupt 15 handling location
	for (i=0; i<sizeof(int15_handler_code); i++)
		*(UINT8*)(UINT64)(int15_vector+i) = int15_handler_code[i];

	VMM_LOG(mask_anonymous, level_trace, "E820 Original vector:0x%x\n",g_int15_orignal_vector );
	VMM_LOG(mask_anonymous, level_trace, "E820 int15 handler vector:0x%x\n",g_int15_trapped_page );
}
#endif //ENABLE_INT15_VIRTUALIZATION
#ifdef DEBUG
INLINE
const char* e820_get_type_name( INT15_E820_RANGE_TYPE type )
{
    return (type < E820_NAMES_COUNT) ? g_int15_e820_type_name[type] : "UNKNOWN";
}
#endif

BOOLEAN e820_abstraction_initialize(const INT15_E820_MEMORY_MAP* e820_memory_map)
{
#ifdef ENABLE_INT15_VIRTUALIZATION
    if(is_unrestricted_guest_supported())
    	//initialize int15 handling vectors
    	update_int15_handling();
#endif
    if (e820_memory_map != NULL) {
        UINT32 size = e820_memory_map->memory_map_size + sizeof(e820_memory_map->memory_map_size);
        g_e820_map = (INT15_E820_MEMORY_MAP*)vmm_memory_alloc(size);
        if (g_e820_map == NULL) {
            return FALSE;
        }
        vmm_memcpy(g_e820_map, e820_memory_map, size);
        VMM_DEBUG_CODE(e820_abstraction_print_memory_map(E820_ORIGINAL_MAP));
        return TRUE;
    }
    return FALSE;
}

BOOLEAN e820_abstraction_is_initialized(void) {
    return (g_e820_map != NULL);
}

const INT15_E820_MEMORY_MAP* e820_abstraction_get_map(E820_HANDLE e820_handle) {
	if (e820_handle == E820_ORIGINAL_MAP) {
		return g_e820_map;
	}

	return (const INT15_E820_MEMORY_MAP*)e820_handle;
}


E820_ABSTRACTION_RANGE_ITERATOR e820_abstraction_iterator_get_first(E820_HANDLE e820_handle) {
    INT15_E820_MEMORY_MAP* e820_map;

    if (e820_handle == E820_ORIGINAL_MAP) {
        e820_map = g_e820_map;
    }
    else {
        e820_map = (INT15_E820_MEMORY_MAP*)e820_handle;
    }

    if (e820_map == NULL) {
        return E820_ABSTRACTION_NULL_ITERATOR;
    }

    if (e820_map->memory_map_size == 0) {
        return E820_ABSTRACTION_NULL_ITERATOR;
    }

    return(E820_ABSTRACTION_RANGE_ITERATOR)(&(e820_map->memory_map_entry[0]));
}

E820_ABSTRACTION_RANGE_ITERATOR
e820_abstraction_iterator_get_next(E820_HANDLE e820_handle, E820_ABSTRACTION_RANGE_ITERATOR iter) {
    UINT64 iter_hva = (UINT64)iter;
    INT15_E820_MEMORY_MAP* e820_map;
    UINT64 e820_entries_hva;

    if (iter == (E820_ABSTRACTION_RANGE_ITERATOR)NULL) {
        return E820_ABSTRACTION_NULL_ITERATOR;
    }

    if (e820_handle == E820_ORIGINAL_MAP) {
        e820_map = g_e820_map;
    }
    else {
        e820_map = (INT15_E820_MEMORY_MAP*)e820_handle;
    }

    if(e820_map == NULL){
        return E820_ABSTRACTION_NULL_ITERATOR;
    }

    e820_entries_hva = (UINT64)(&(e820_map->memory_map_entry[0]));

    iter_hva += sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    if (iter_hva >= (e820_entries_hva + e820_map->memory_map_size)) {
        return E820_ABSTRACTION_NULL_ITERATOR;
    }

    return (E820_ABSTRACTION_RANGE_ITERATOR*)iter_hva;
}

const INT15_E820_MEMORY_MAP_ENTRY_EXT*
e820_abstraction_iterator_get_range_details(IN E820_ABSTRACTION_RANGE_ITERATOR iter) {
    if (iter == (E820_ABSTRACTION_RANGE_ITERATOR)NULL) {
        return NULL;
    }

    return (INT15_E820_MEMORY_MAP_ENTRY_EXT*)iter;
}


BOOLEAN e820_abstraction_create_new_map(OUT E820_HANDLE* handle) {
    INT15_E820_MEMORY_MAP* e820_map = (INT15_E820_MEMORY_MAP*)vmm_page_alloc(1);
    if (e820_map == NULL) {
        return FALSE;
    }

    e820_map->memory_map_size = 0;

    *handle = (E820_HANDLE)e820_map;
    return TRUE;
}

void e820_abstraction_destroy_map(IN E820_HANDLE handle) {
    if (handle == E820_ORIGINAL_MAP) {
        // Destroying of original map is forbidden
        VMM_ASSERT(0);
        return;
    }
    vmm_page_free((void*)handle);
}

BOOLEAN e820_abstraction_add_new_range(IN E820_HANDLE handle,
                                       IN UINT64 base_address,
                                       IN UINT64 length,
                                       IN INT15_E820_RANGE_TYPE  address_range_type,
                                       IN INT15_E820_MEMORY_MAP_EXT_ATTRIBUTES extended_attributes) {
    INT15_E820_MEMORY_MAP* e820_map = (INT15_E820_MEMORY_MAP*)handle;
    INT15_E820_MEMORY_MAP_ENTRY_EXT* new_entry;
    UINT32 new_entry_index;

    if (handle == E820_ORIGINAL_MAP) {
        VMM_ASSERT(0);
        return FALSE;
    }

    if ((e820_map->memory_map_size + sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT)) >= PAGE_4KB_SIZE) {
        return FALSE;
    }

    if (length == 0) {
        return FALSE;
    }

    new_entry_index = e820_map->memory_map_size / sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);

    if (new_entry_index > 0) {
        INT15_E820_MEMORY_MAP_ENTRY_EXT* last_entry = &(e820_map->memory_map_entry[new_entry_index - 1]);
        if ((last_entry->basic_entry.base_address >= base_address) ||
            (last_entry->basic_entry.base_address + last_entry->basic_entry.length > base_address)) {
            return FALSE;
        }
    }

    new_entry = &(e820_map->memory_map_entry[new_entry_index]);
    new_entry->basic_entry.base_address = base_address;
    new_entry->basic_entry.length = length;
    new_entry->basic_entry.address_range_type = address_range_type;
    new_entry->extended_attributes.uint32 = extended_attributes.uint32;
    e820_map->memory_map_size += sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT);
    return TRUE;
}

#ifdef ENABLE_INT15_VIRTUALIZATION
// handle int15 from real mode code
// we use CS:IP for vmcall instruction to get indication that there is int15
// check for E820 function, if true, then handle it
// no other int15 function should come here
BOOLEAN handle_int15_vmcall(GUEST_CPU_HANDLE gcpu)
{
	UINT16	selector=0;
	UINT64  base=0;
	UINT32  limit=0;
	UINT32  attr=0;
	UINT32 expected_lnr_addr;
	UINT32 vmcall_lnr_addr;
	volatile UINT64	r_rax=0, r_rdx=0, r_rip=0;

	if(!(0x1 & gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0))) //PE = 0? then real mode
	{
		//need to get CS:IP to make sure that this VMCALL from INT15 handler
		gcpu_get_segment_reg(gcpu,IA32_SEG_CS, &selector,&base,&limit,&attr);
		r_rip = gcpu_get_gp_reg(gcpu, IA32_REG_RIP);

		expected_lnr_addr = SEGMENT_OFFSET_TO_LINEAR(g_int15_trapped_page >> 16,
												g_int15_trapped_page + VMCALL_OFFSET);
		vmcall_lnr_addr = SEGMENT_OFFSET_TO_LINEAR((UINT32)selector, (UINT32)r_rip);

	    //check to see if the CS:IP is same as expected for VMCALL in INT15 handler
	   	if (expected_lnr_addr == vmcall_lnr_addr)
	    {
			r_rax = gcpu_get_gp_reg(gcpu, IA32_REG_RAX);
	   		r_rdx = gcpu_get_gp_reg(gcpu, IA32_REG_RDX);
	    	if ((0xE820 == r_rax) && ('SMAP' == r_rdx))
	    	{
				if (g_emap == NULL) {
					g_emap = vmm_malloc(sizeof(E820MAP_STATE));
					VMM_ASSERT(g_emap != NULL);
					vmm_memset(g_emap, 0, sizeof(E820MAP_STATE));
				}
				e820_save_guest_state(gcpu, g_emap);
				g_emap->guest_handle = gcpu_guest_handle(gcpu);
				e820_int15_handler(g_emap);
				e820_restore_guest_state(gcpu, g_emap);
				gcpu_skip_guest_instruction(gcpu);
				return TRUE;
	    	} else {

	    		 VMM_LOG(mask_anonymous, level_error,"INT15 wasn't handled for function 0x%x\n", r_rax);
	    		 VMM_DEADLOOP(); // Should not get here
	    		 return FALSE;
	    	}

	    }
	}
	return FALSE;
}

//save Guest state for registers we might be using
// when handling INT15 E820
void
e820_save_guest_state(GUEST_CPU_HANDLE gcpu, E820MAP_STATE *emap)
{
	UINT16            selector;
	UINT64            base;
	UINT32            limit;
	UINT32            attr;
	E820_GUEST_STATE *p_arch = &emap->e820_guest_state;

	//only registers needed for handling int15 are saved
	p_arch->em_rax = gcpu_get_gp_reg(gcpu, IA32_REG_RAX);
	p_arch->em_rbx = gcpu_get_gp_reg(gcpu, IA32_REG_RBX);
	p_arch->em_rcx = gcpu_get_gp_reg(gcpu, IA32_REG_RCX);
	p_arch->em_rdx = gcpu_get_gp_reg(gcpu, IA32_REG_RDX);
	p_arch->em_rdi = gcpu_get_gp_reg(gcpu, IA32_REG_RDI);
	p_arch->em_rsp = gcpu_get_gp_reg(gcpu, IA32_REG_RSP);
	p_arch->em_rflags = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);

	gcpu_get_segment_reg(gcpu,IA32_SEG_ES, &selector,&base,&limit,&attr);
	p_arch->em_es = selector; p_arch->es_base = base; p_arch->es_lim = limit;
	p_arch->es_attr = attr;
	gcpu_get_segment_reg(gcpu,IA32_SEG_SS, &selector,&base,&limit,&attr);
	p_arch->em_ss = selector; p_arch->ss_base = base; p_arch->ss_lim = limit;
	p_arch->ss_attr = attr;
}

//update VMCS state after handling INT15 E820
void
e820_restore_guest_state( GUEST_CPU_HANDLE gcpu, E820MAP_STATE *emap)
{
	E820_GUEST_STATE *p_arch = &emap->e820_guest_state;
	GPA	sp_gpa_addr;
	HVA	sp_hva_addr;
	UINT16	sp_gpa_val;

	//only registers which could be modified by the handler
	//will be restored.
	gcpu_set_gp_reg(gcpu, IA32_REG_RAX,p_arch->em_rax);
	gcpu_set_gp_reg(gcpu, IA32_REG_RBX,p_arch->em_rbx);
	gcpu_set_gp_reg(gcpu, IA32_REG_RCX,p_arch->em_rcx);
	gcpu_set_gp_reg(gcpu, IA32_REG_RDX,p_arch->em_rdx);
	gcpu_set_gp_reg(gcpu, IA32_REG_RDI,p_arch->em_rdi);

	// we need to change the modify EFLAGS saved in stack
	// as when we do IRET, EFLAGS are restored from the stack
	//only IRET, CPU does pop IP, pop CS_Segment, Pop EFLAGS
	// in real mode these pos are only 2bytes
	sp_gpa_addr = SEGMENT_OFFSET_TO_LINEAR((UINT32)p_arch->em_ss, p_arch->em_rsp);
	sp_gpa_addr +=4; //RSP points to RIP:SEGMENT:EFLAGS so we increment 4 to get to EFLAGS register

    if (FALSE == gpm_gpa_to_hva(emap->guest_phy_memory, sp_gpa_addr, &sp_hva_addr))
   {
	 VMM_LOG(mask_anonymous, level_trace,"Translation failed for physical address %P \n", sp_gpa_addr);
     VMM_DEADLOOP();
     return;
   }

	sp_gpa_val = *(UINT16*)(UINT64)sp_hva_addr;

	if (p_arch->em_rflags & RFLAGS_CARRY)
	  BITMAP_SET(sp_gpa_val, RFLAGS_CARRY);
	else
	  BITMAP_CLR(sp_gpa_val, RFLAGS_CARRY);

	*(UINT16*)(UINT64)sp_hva_addr =   sp_gpa_val;
}

//handle INT15 E820 map
BOOLEAN
e820_int15_handler(E820MAP_STATE *emap)
{
    UINT64 dest_gpa;

	E820_GUEST_STATE *p_arch = &emap->e820_guest_state;
    const INT15_E820_MEMORY_MAP *p_mmap=NULL;

    if (emap->guest_phy_memory == NULL)
    	emap->guest_phy_memory = gcpu_get_current_gpm(emap->guest_handle);

    VMM_ASSERT(emap->guest_phy_memory != NULL);

	if (NULL == emap->emu_e820_handle)
	{
		if (FALSE == (gpm_create_e820_map(emap->guest_phy_memory, (E820_HANDLE)&emap->emu_e820_handle)))
		{
			 VMM_LOG(mask_anonymous, level_error,"FATAL ERROR: No E820 Memory Map was found\n");
			 VMM_DEADLOOP();
			 return FALSE;
		}
		p_mmap = e820_abstraction_get_map(emap->emu_e820_handle);
		emap->emu_e820_memory_map = p_mmap->memory_map_entry;
		emap->emu_e820_memory_map_size =
				(UINT16) (p_mmap->memory_map_size / sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT));
		VMM_ASSERT(NULL != emap->emu_e820_memory_map && 0 != emap->emu_e820_memory_map_size);
		emap->emu_e820_continuation_value = 0;
		VMM_LOG(mask_anonymous, level_trace,"INT15 vmcall for E820 map initialized!\n" );
	}
   //
   // Make sure all the arguments are valid
   //
   if ((p_arch->em_rcx < sizeof(INT15_E820_MEMORY_MAP_ENTRY)) ||
       (p_arch->em_rbx >= emap->emu_e820_memory_map_size)    ||
       (p_arch->em_rbx != 0 && p_arch->em_rbx != emap->emu_e820_continuation_value))
   {
       //
       // Set the carry flag
       //
       BITMAP_SET(p_arch->em_rflags, RFLAGS_CARRY);
       VMM_LOG(mask_anonymous, level_error, "ERROR>>>>> E820 INT15 rbx=0x%x rcx:0x%x\n",p_arch->em_rbx,p_arch->em_rcx);

   }
   else
   {
	   HVA dest_hva=0;

       // CX contains number of bytes to write.
       // here we select between basic entry and extended
       p_arch->em_rcx = (p_arch->em_rcx >= sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT)) ?
           sizeof(INT15_E820_MEMORY_MAP_ENTRY_EXT) :
           sizeof(INT15_E820_MEMORY_MAP_ENTRY);

       // where to put the result
       dest_gpa = SEGMENT_OFFSET_TO_LINEAR((UINT32) p_arch->em_es, p_arch->em_rdi);

       if (FALSE == gpm_gpa_to_hva(emap->guest_phy_memory, dest_gpa, &dest_hva))
       {
		 VMM_LOG(mask_anonymous, level_trace,"Translation failed for physical address %P \n", dest_gpa);
	     BITMAP_SET(p_arch->em_rflags, RFLAGS_CARRY);
	     return FALSE;
       }
       vmm_memcpy((void*)dest_hva, (unsigned char *) &emap->emu_e820_memory_map[p_arch->em_rbx],
    		   	   	   	   	   	   	   	   	   	   	   	   	   (unsigned int) p_arch->em_rcx);

       // keep, to validate next instruction
       emap->emu_e820_continuation_value = (UINT16) p_arch->em_rbx + 1;

       // prepare output parameters
       p_arch->em_rax = 'SMAP';

       // Clear the carry flag which means error absence
       BITMAP_CLR(p_arch->em_rflags, RFLAGS_CARRY);

       if (emap->emu_e820_continuation_value >= emap->emu_e820_memory_map_size)
       {
          // Clear EBX to indicate that this is the last entry in the memory map
    	   p_arch->em_rbx = 0;
    	   emap->emu_e820_continuation_value = 0;


       }
       else
       {
           // Update the EBX continuation value to indicate there are more entries
    	   p_arch->em_rbx = emap->emu_e820_continuation_value;

       }
   }

   return TRUE;
}
#endif //ENABLE_INT15_VIRTUALIZATION

#ifdef DEBUG
void e820_abstraction_print_memory_map(IN E820_HANDLE handle) {
    INT15_E820_MEMORY_MAP* e820_map = (INT15_E820_MEMORY_MAP*)handle;
    UINT32 num_of_entries;
    UINT32 i;

    if (e820_map == E820_ORIGINAL_MAP) {
        e820_map = g_e820_map;
    }

    VMM_LOG(mask_anonymous, level_trace,"\nE820 Memory Map\n");
    VMM_LOG(mask_anonymous, level_trace,"-------------------\n");

    if (e820_map == NULL) {
        VMM_LOG(mask_anonymous, level_trace,"DOESN'T EXIST!!!\n");
    }

    num_of_entries = e820_map->memory_map_size / sizeof(e820_map->memory_map_entry[0]);

    for (i = 0; i < num_of_entries; i++) {
        INT15_E820_MEMORY_MAP_ENTRY_EXT* entry = &(e820_map->memory_map_entry[i]);
        VMM_LOG(mask_anonymous, level_trace,"%2d: [%P : %P] ; type = 0x%x(%8s) ; ext_attr = 0x%x\n",
                i,
                entry->basic_entry.base_address,
                entry->basic_entry.base_address + entry->basic_entry.length,
                entry->basic_entry.address_range_type,
                e820_get_type_name(entry->basic_entry.address_range_type),
                entry->extended_attributes.uint32);
    }
    VMM_LOG(mask_anonymous, level_trace,"-------------------\n");
}
#endif
