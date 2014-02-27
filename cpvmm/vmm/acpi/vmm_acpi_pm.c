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

#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "heap.h"
#include "hw_utils.h"
#include "hw_interlocked.h"
#include "hw_vmx_utils.h"
#include "em64t_defs.h"
#include "ia32_defs.h"
#include "gdt.h"
#include "isr.h"
#include "guest_cpu.h"
#include "vmm_objects.h"
#include "vmcs_api.h"
#include "vmcs_init.h"
#include "scheduler.h"
#include "vmexit_io.h"
#include "ipc.h"
#include "host_memory_manager_api.h"
#include "pat_manager.h"
#include "host_cpu.h"
#include "startap.h"
#include "vmm_stack_api.h"
#include "vmm_bootstrap_utils.h"
#include "event_mgr.h"

#include "vmm_globals.h"
#include "ept.h"
#include "vmm_events_data.h"

#include "unrestricted_guest.h"
#include "file_codes.h"

#include "vmm_acpi.h"
#include "vmm_callback.h"


#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_ACPI_PM_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_ACPI_PM_C, __condition)
#ifdef USE_ACPI
#pragma warning( disable : 4100 ) // not used parameter

extern VMM_STARTUP_STRUCT vmm_startup_data;

extern void vmm_debug_port_clear(void);
extern void vmm_io_init(void);
extern void memory_dump(const void *mem_location, UINT32 count, UINT32 size);
extern void vmm_acpi_resume_after_s3_c_main_gnu(void);
UINT32 g_s3_resume_flag=0;

/*------------------------------Types and Macros------------------------------*/

//#define BREAK_AT_FIRST_COMMAND

#define PTCH 0x00   // must be patched

#define PTR_TO_U32(__p) (UINT32) (size_t) (__p)

#define WAIT_FOR_MP_CONDITION(__cond) { while ( ! (__cond)) hw_pause(); }

#define REALMODE_SEGMENT_SELECTOR_TO_BASE(__selector) (((UINT32) (__selector)) << 4)

#define MAX_ACPI_CALLBACKS      10

// See "4.7.3.2.1 PM1 Control Registers" in ACPIspec30b
#define SLP_EN(PM1x_CNT_BLK) (((PM1x_CNT_BLK) >> 13) & 0x1)
#define SLP_TYP(PM1x_CNT_BLK) (((PM1x_CNT_BLK) >> 10) & 0x7)

// Describes GP, Flags, Segment and XDT registers as they are stored on the
// stack. The order is important and defined partially by HW (pusha implementation)
// and partially by hardocded piece of code.
typedef struct _CPU_SNAPSHOT_S {
    IA32_GDTR   gdtr;
    IA32_GDTR   idtr;
    UINT16      gs;
    UINT16      fs;
    UINT16      es;
    UINT16      ss;
    UINT16      ds;
    UINT16      cs;
    UINT32      eflags;
    UINT32      edi;
    UINT32      esi;
    UINT32      ebp;
    UINT32      esp;
    UINT32      ebx;
    UINT32      edx;
    UINT32      ecx;
    UINT32      eax;
} CPU_SNAPSHOT_S;

typedef struct _VMM_S3_PROTECTED_RESUME_CODE_2 {
    UINT8          code[72];
    IA32_GDTR      vmm_gdtr[1];
} VMM_S3_PROTECTED_RESUME_CODE_2;

typedef struct {
    UINT8                           real_code[82];//Currently 82-byte is long enough to hold the s3_resume_real_mode_code.
    IA32_GDTR                       gdtr[1];
    UINT8                           pad[8];
    UINT8                           low_memory_gdt[TSS_FIRST_GDT_ENTRY_OFFSET]; // aligned on 16 bytes
    VMM_S3_PROTECTED_RESUME_CODE_2  protected_code[1];
    UINT8                           stack[sizeof(CPU_SNAPSHOT_S) + 16];
} VMM_S3_REAL_MODE_RESUME_LAYOUT;

typedef struct {
    UINT8                           protected_code_1[30];
    VMM_S3_PROTECTED_RESUME_CODE_2  protected_code_2[1];
    UINT8                           stack[sizeof(CPU_SNAPSHOT_S) + 16];
} VMM_S3_PROTECTED_RESUME_LAYOUT;



#ifdef BREAK_AT_FIRST_COMMAND
    #define REAL_MODE_BASE_OFFSET 2
#else
    #define REAL_MODE_BASE_OFFSET 0
#endif

#define REALMODE_GDTR_OFFSET            OFFSET_OF(VMM_S3_REAL_MODE_RESUME_LAYOUT, gdtr)

// this offset is used to fix the S3 failure issue on Lenovo T410i laptop
#define ZERO_ESP_CODE_BYTE_SIZE 3

#define REALMODE_SS_VALUE_PATCH_LOCATION                (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 2)
#define REALMODE_SP_VALUE_PATCH_LOCATION                (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 7)
#define REALMODE_CODE_START_ALIGNED_16_PATCH_LOCATION   (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 51)
#define REALMODE_GDTR_OFFSET_PATCH_LOCATION             (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 57)
#define REALMODE_PROTECTED_OFFSET_PATCH_LOCATION        (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 72)
#define REALMODE_PROTECTED_SEGMENT_PATCH_LOCATION       (REAL_MODE_BASE_OFFSET + ZERO_ESP_CODE_BYTE_SIZE + 76)

static UINT8 s3_resume_real_mode_code[] =
{
#ifdef BREAK_AT_FIRST_COMMAND
    0xEB, 0xFE,                     // jmp $
#endif
    // at the end of the sequence ESI points to the beginning of the snapshot
    0xFA,                           // 00: cli

    // define ZERO_ESP_CODE_BYTE_SIZE = 3, as the byte size is 3
    0x66, 0x33, 0xE4,               // xor esp, esp   ;; do not assume the high part of esp is zero

    0xBC, PTCH, PTCH,               // 01: mov     sp, immediate
    0x8E, 0xD4,                     // 04: mov     ss, sp
    0xBC, PTCH, PTCH,               // 06: mov     sp, immediate

    0x66, 0x60,                     // 09: pushad
    0x66, 0x9C,                     // 11: pushfd
    0x0E,                           // 13: push     cs
    0x1E,                           // 14: push     ds
    0x16,                           // 15: push     ss
    0x06,                           // 16: push     es
    0x0F, 0xA0,                     // 17: push     fs
    0x0F, 0xA8,                     // 19: push     gs
    0x66, 0x33, 0xF6,               // 21: xor      esi, esi ;; provide high part of esi is zero
    0x8B, 0xF4,                     // 24: mov      si, sp
    0x16,                           // 26: push     ss
    0x1F,                           // 27: pop      ds      ;; now ds:si points to ss:sp
    0x83, 0xEE, 0x06,               // 28: sub      si, 6
    0x0F, 0x01, 0x0C,               // 31: sidt     fword ptr [si]
    0x83, 0xEE, 0x06,               // 34: sub      si, 6
    0x0F, 0x01, 0x04,               // 37: sgdt     fword ptr [si]
    // at this point all data is stored. ds:si points to the start of the snapshot
    // We need to deliver address further. Convert it to linear and put into esi
    0x66, 0x8C, 0xD8,               // 40: mov      eax, ds
    0x66, 0xC1, 0xE0, 0x04,         // 43: shl      eax, 4
    0x66, 0x03, 0xF0,               // 47: add      esi, eax  ;; now esi contains linear address of snapshot
    0xB8, PTCH, PTCH,               // 50: mov  ax, CODE_START_ALIGNED_16
    0x8E, 0xD8,                     // 53: mov  ds, ax
    0x8D, 0x3E, PTCH, PTCH,         // 55: lea  di, REALMODE_GDTR_OFFSET
    0x0F, 0x01, 0x15,               // 59: lgdt fword ptr [di]
    0x0F, 0x20, 0xC0,               // 62: mov  eax, cr0
    0x0C, 0x01,                     // 65: or   al, 1
    0x0F, 0x22, 0xC0,               // 67: mov  cr0, eax
    0x66, 0xEA,                     // 70: fjmp PROTECTED_SEGMENT,PROTECTED_OFFSET
    PTCH, PTCH, PTCH, PTCH,         // 72: PROTECTED_OFFSET
    PTCH, PTCH,                     // 76: PROTECTED_SEGMENT
};

static UINT8 s3_resume_protected_code_1[] =
{
#ifdef BREAK_AT_FIRST_COMMAND
    0xEB, 0xFE,                     // 00: jmp $
#else
    0x90, 0x90,                     // 00: nop, nop
#endif
    // Save CPU registers in the old stack.
    0xFA,                           // 02: cli
    0x60,                           // 03: pushad
    0x9C,                           // 04: pushfd
    0x0E,                           // 05: push     cs
    0x1E,                           // 06: push     ds
    0x16,                           // 07: push     ss
    0x06,                           // 08: push     es
    0x0F, 0xA0,                     // 09: push     fs
    0x0F, 0xA8,                     // 11: push     gs
    0x8B, 0xF4,                     // 13: mov      esi, esp
    0x16,                           // 15: push     ss
    0x1F,                           // 16: pop      ds       ;; now ds:si points to ss:sp
    0x83, 0xEE, 0x06,               // 17: sub      esi, 6
    0x0F, 0x01, 0x0E,               // 20: sidt     fword ptr [esi]
    0x83, 0xEE, 0x06,               // 23: sub      esi, 6
    0x0F, 0x01, 0x06,               // 26: sgdt     fword ptr [esi]
    // at this point all data is stored. ds:si points to the start of the snapshot
    // We need to deliver address further. Convert it to linear and put into esi. tbd
};

#define PROTECTED_CODE_DS_VALUE_PATCH_LOCATION      2
#define PROTECTED_CODE_GDTR_PATCH_LOCATION          22
#define PROTECTED_CODE_CPU_SNAPSHOT_ADDR_PATCH_LOCATION 28
#define PROTECTED_CODE_CPU_SNAPSHOT_SIZE_PATCH_LOCATION 33
#define PROTECTED_CODE_ESP_PATCH_LOCATION           40
#define PROTECTED_CODE_ENTRY_POINT_PATCH_LOCATION   45
#define PROTECTED_CODE_STARTUP_PTR_PATCH_LOCATION   50
#define PROTECTED_CODE_INIT64_PATCH_LOCATION        55
#define PROTECTED_CODE_INIT32_PATCH_LOCATION        60
#define PROTECTED_CODE_STARTAP_MAIN_PATCH_LOCATION  65

static UINT8 s3_resume_protected_code_2[] =
{
    //==Initialize VMM environment. It is the entry point from RealMode code==
    0x66, 0xB8, PTCH, PTCH,         // 00: mov         ax,ds_value
    0x66, 0x8E, 0xD8,               // 04: mov         ds,ax
    0x66, 0x8E, 0xC0,               // 07: mov         es,ax
    0x66, 0x8E, 0xE0,               // 10: mov         fs,ax
    0x66, 0x8E, 0xE8,               // 13: mov         gs,ax
    0x66, 0x8E, 0xD0,               // 16: mov         ss,ax
    0x0F, 0x01, 0x15, PTCH, PTCH, PTCH, PTCH, // 19: lgdt fword ptr [gdtr]
    // copy saved CPU snapshot from old stack to static buffer
    0x8D, 0x3D, PTCH, PTCH, PTCH, PTCH, // 26: lea     edi, cpu_saved_state
    0xB9, PTCH, PTCH, PTCH, PTCH,       // 32: mov     ecx, sizeof(cpu_saved_state)
    0xF3, 0xA4,                         // 37: rep     movsb
    // Prepare arguments prior calling thunk
    0xBC, PTCH, PTCH, PTCH, PTCH,   // 39: mov         esp,im32
    0x68, PTCH, PTCH, PTCH, PTCH,   // 44: push        entry_point
    0x68, PTCH, PTCH, PTCH, PTCH,   // 49: push        p_startup
    0x68, PTCH, PTCH, PTCH, PTCH,   // 54: push        p_init64
    0x68, PTCH, PTCH, PTCH, PTCH,   // 59: push        p_init32
    0xB9, PTCH, PTCH, PTCH, PTCH,   // 64: mov         ecx,startap_main
    0xFF, 0xD1                      // 69: call        dword ptr [ecx]
};

/*------------------------------Local Variables-------------------------------*/
static IO_PORT_ID pm_port[ACPI_PM1_CNTRL_REG_COUNT];
static INIT32_STRUCT *init32_data_p = NULL;   // set as NULL, it is only useful in MP mode (StartAP uses it) and set by setup_data_for_s3() when boot processor > 1;
static INIT64_STRUCT init64_data;
static UINT8 s3_original_waking_code[sizeof(VMM_S3_REAL_MODE_RESUME_LAYOUT)];
static void * vmm_waking_vector;
static INT32 number_of_started_cpus;
static INT32 number_of_stopped_cpus;
static VMM_GUEST_CPU_STARTUP_STATE s3_resume_bsp_gcpu_initial_state;
static CPU_SNAPSHOT_S cpu_saved_state;
static vmm_acpi_callback suspend_callbacks[MAX_ACPI_CALLBACKS] = {0};
static vmm_acpi_callback resume_callbacks[MAX_ACPI_CALLBACKS] = {0};

/*------------------Forward Declarations for Local Functions------------------*/
static BOOLEAN vmm_acpi_pm1x_handler(
    GUEST_CPU_HANDLE  gcpu,
    UINT16            port_id,
    unsigned          port_size,
    RW_ACCESS         access,
    BOOLEAN           string_intr,	// ins/outs
    BOOLEAN           rep_prefix,	// rep 
    UINT32            rep_count,
    void             *p_value,
    void             *context
    );

static VMM_STATUS vmm_acpi_prepare_for_s3(GUEST_CPU_HANDLE gcpu);

void CDECL vmm_acpi_resume_after_s3_c_main(
    UINT32 cpu_id,
    UINT64 startup_struct_u,
    UINT64 application_params_struct_u,
    UINT64 reserved
    );
static void vmm_acpi_prepare_init64_data(void);
static void vmm_acpi_prepare_init32_data(UINT32 low_memory_page_address);
static void vmm_acpi_build_s3_resume_real_mode_layout(UINT32 waking_vector);
static void vmm_acpi_build_s3_resume_protected_layout(void *p_waking_vector);
static void vmm_acpi_build_s3_resume_protected_code(VMM_S3_PROTECTED_RESUME_CODE_2 *);
static void vmm_acpi_prepare_cpu_for_s3(CPU_ID from, void *unused);
static void vmm_acpi_save_original_waking_code(void *p_waking_vector);
static void vmm_acpi_restore_original_waking_code(void);
static void vmm_acpi_fill_bsp_gcpu_initial_state(GUEST_CPU_HANDLE gcpu);
static void vmm_acpi_notify_on_platform_suspend(void);
static void vmm_acpi_notify_on_platform_resume(void);


/*-----------------------------C-Code Starts Here-----------------------------*/

void vmm_acpi_save_original_waking_code(void *p_waking_vector)
{
    vmm_waking_vector = p_waking_vector;
    vmm_memcpy(s3_original_waking_code, vmm_waking_vector, sizeof(s3_original_waking_code));
}

void vmm_acpi_restore_original_waking_code(void)
{
    vmm_memcpy(vmm_waking_vector, s3_original_waking_code, sizeof(s3_original_waking_code));
}

/*void dump_s3_resume_real_mode_code(VMM_S3_REAL_MODE_RESUME_LAYOUT *p_layout)
{
    VMM_LOG(mask_anonymous, level_trace,"\n>>>   Real Mode Code\n");
    memory_dump(p_layout->real_code, sizeof(p_layout->real_code), 1);

    VMM_LOG(mask_anonymous, level_trace,"\n>>>   GDTR  base=%P  limit=%P\n", p_layout->gdtr->base, p_layout->gdtr->limit);

    VMM_LOG(mask_anonymous, level_trace,"\n>>>   GDT\n");
    memory_dump(p_layout->low_memory_gdt, sizeof(p_layout->low_memory_gdt) / 4, 4);

    VMM_LOG(mask_anonymous, level_trace,"\n>>>   Protected\n");
    memory_dump(p_layout->protected_code->code, sizeof(p_layout->protected_code->code), 1);

    VMM_LOG(mask_anonymous, level_trace,"\n>>>   vmm_gdtr  base=%P  limit=%P\n",
        p_layout->protected_code->vmm_gdtr->base,
        p_layout->protected_code->vmm_gdtr->limit);
}*/

void vmm_acpi_build_s3_resume_protected_code(VMM_S3_PROTECTED_RESUME_CODE_2 *p_protected)
{
    EM64T_GDTR gdtr;
    HVA stack_pointer;
    UINT8 *pcode = p_protected->code;

    // save original GDTR
    hw_sgdt(&gdtr);
    p_protected->vmm_gdtr->base = (UINT32) gdtr.base;
    p_protected->vmm_gdtr->limit = TSS_FIRST_GDT_ENTRY_OFFSET - 1;

    VMM_ASSERT(sizeof(p_protected->code) > sizeof(s3_resume_protected_code_2));
    // copy non-patched protected code to waking vector area
    vmm_memcpy(pcode, s3_resume_protected_code_2, sizeof(s3_resume_protected_code_2));

    // patch DS value in mov ax, ds_val
    *(UINT16 *) &pcode[PROTECTED_CODE_DS_VALUE_PATCH_LOCATION] = DATA32_GDT_ENTRY_OFFSET;

    // patch GDTR
    *(UINT32 *) &pcode[PROTECTED_CODE_GDTR_PATCH_LOCATION] = PTR_TO_U32(p_protected->vmm_gdtr);

    // patch CPU snapshot location and size
    *(UINT32 *) &pcode[PROTECTED_CODE_CPU_SNAPSHOT_ADDR_PATCH_LOCATION] = PTR_TO_U32(&cpu_saved_state);
    *(UINT32 *) &pcode[PROTECTED_CODE_CPU_SNAPSHOT_SIZE_PATCH_LOCATION] = sizeof(cpu_saved_state);

    // patch ESP
    vmm_stack_get_stack_pointer_for_cpu(0, &stack_pointer);
    *(UINT32 *) &pcode[PROTECTED_CODE_ESP_PATCH_LOCATION] = (UINT32) stack_pointer - 512;

    // patch VMM entry point
#ifdef __GNUC__
    *(UINT32 *) &pcode[PROTECTED_CODE_ENTRY_POINT_PATCH_LOCATION] = PTR_TO_U32(vmm_acpi_resume_after_s3_c_main_gnu);
#else
    *(UINT32 *) &pcode[PROTECTED_CODE_ENTRY_POINT_PATCH_LOCATION] = PTR_TO_U32(vmm_acpi_resume_after_s3_c_main);
#endif
    // patch VMM startup structure address
    *(UINT32 *) &pcode[PROTECTED_CODE_STARTUP_PTR_PATCH_LOCATION] = PTR_TO_U32(&vmm_startup_data);

    // patch INIT64 structure address
    *(UINT32 *) &pcode[PROTECTED_CODE_INIT64_PATCH_LOCATION] = PTR_TO_U32(&init64_data);

    // patch INIT32 structure address
    *(UINT32 *) &pcode[PROTECTED_CODE_INIT32_PATCH_LOCATION] = PTR_TO_U32(init32_data_p);

    // patch startap module entry point
    *(UINT32 *) &pcode[PROTECTED_CODE_STARTAP_MAIN_PATCH_LOCATION] = (UINT32) vmm_startup_data.vmm_memory_layout[thunk_image].entry_point;

    VMM_LOG(mask_anonymous, level_trace,"startap entry point = %P\n", vmm_startup_data.vmm_memory_layout[thunk_image].entry_point);
}


void vmm_acpi_build_s3_resume_real_mode_layout(UINT32 waking_vector)
{
    VMM_S3_REAL_MODE_RESUME_LAYOUT *p_layout;
    EM64T_GDTR gdtr;
    UINT16 waking_code_segment;
    UINT32 stack_base;
    UINT32 sp;
    UINT32 ss;

    p_layout = (VMM_S3_REAL_MODE_RESUME_LAYOUT *) (size_t) waking_vector;

    // clone GDT into low memory, so real-mode code can access it
    hw_sgdt(&gdtr);
    vmm_memcpy(p_layout->low_memory_gdt, (void *) gdtr.base, sizeof(p_layout->low_memory_gdt));

    // prepare GDTR to point to GDT
    p_layout->gdtr->base  = PTR_TO_U32(p_layout->low_memory_gdt);
    p_layout->gdtr->limit = TSS_FIRST_GDT_ENTRY_OFFSET - 1;

    VMM_ASSERT(sizeof(p_layout->real_code) > sizeof(s3_resume_real_mode_code));
    // copy real mode waking code
    vmm_memcpy(p_layout->real_code, s3_resume_real_mode_code, sizeof(s3_resume_real_mode_code));


    // patch SS and SP
    stack_base =  PTR_TO_U32(p_layout->stack);
    ss = stack_base >> 4;
    sp = stack_base + sizeof(p_layout->stack) - REALMODE_SEGMENT_SELECTOR_TO_BASE(ss);

    *(UINT16 *) &p_layout->real_code[REALMODE_SS_VALUE_PATCH_LOCATION] = (UINT16)ss;
    *(UINT16 *) &p_layout->real_code[REALMODE_SP_VALUE_PATCH_LOCATION] = (UINT16)sp;

    // patch real code segment
    waking_code_segment = (UINT16) (waking_vector >> 4);
    *(UINT16 *)&p_layout->real_code[REALMODE_CODE_START_ALIGNED_16_PATCH_LOCATION] = waking_code_segment;

    // patch GDTR
    *(UINT16 *) &p_layout->real_code[REALMODE_GDTR_OFFSET_PATCH_LOCATION] = REALMODE_GDTR_OFFSET;

    // patch protected mode offset and segment
    *(UINT32 *) &p_layout->real_code[REALMODE_PROTECTED_OFFSET_PATCH_LOCATION] = PTR_TO_U32(p_layout->protected_code);
    *(UINT16 *) &p_layout->real_code[REALMODE_PROTECTED_SEGMENT_PATCH_LOCATION] = CODE32_GDT_ENTRY_OFFSET;

    vmm_acpi_build_s3_resume_protected_code(p_layout->protected_code);
}


void vmm_acpi_build_s3_resume_protected_layout(void *p_waking_vector)
{
    VMM_S3_PROTECTED_RESUME_LAYOUT *p_layout;

    p_layout = (VMM_S3_PROTECTED_RESUME_LAYOUT *) p_waking_vector;

    VMM_ASSERT(sizeof(p_layout->protected_code_1) > sizeof(s3_resume_protected_code_1));
    // copy real mode waking code
    vmm_memcpy(p_layout->protected_code_1, s3_resume_protected_code_1, sizeof(s3_resume_protected_code_1));
    vmm_acpi_build_s3_resume_protected_code(p_layout->protected_code_2);
}


void vmm_acpi_pm_initialize(GUEST_ID guest_id)
{
    unsigned    i;
    UINT8       port_size;
    static BOOLEAN acpi_initialized = FALSE;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(FALSE == acpi_initialized);
    acpi_initialized = TRUE;

    vmm_memset(&s3_resume_bsp_gcpu_initial_state, 0, sizeof(VMM_GUEST_CPU_STARTUP_STATE));
    port_size = vmm_acpi_pm_port_size();

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(2 == port_size || 4 == port_size);

    if (2 == port_size || 4 == port_size) {
        pm_port[0] = (IO_PORT_ID) vmm_acpi_pm_port_a();
        pm_port[1] = (IO_PORT_ID) vmm_acpi_pm_port_b();

        for (i = 0; i < NELEMENTS(pm_port); ++i) {
            if (0 != pm_port[i]) {
                VMM_LOG(mask_anonymous, level_trace,"[ACPI] Install handler at Pm1%cControlBlock(%P)\n", 'a'+i, pm_port[i]);
                io_vmexit_handler_register(guest_id, pm_port[i], vmm_acpi_pm1x_handler, NULL);
            }
        }
    }
    else {
        VMM_LOG(mask_anonymous, level_trace,"[ACPI] Failed to intitalize due to bad port size(%d)\n", port_size);
    }
}

BOOLEAN vmm_acpi_pm1x_handler( GUEST_CPU_HANDLE  gcpu,
        UINT16            port_id,
        unsigned          port_size,
        RW_ACCESS         access,
        BOOLEAN           string_intr,	// ins/outs
        BOOLEAN           rep_prefix,	// rep 
        UINT32            rep_count,      
        void             *p_value,
        void             *context UNUSED)
{
    unsigned pm_reg_id;
    unsigned sleep_state;
    UINT32   value;
    BOOLEAN sleep_enable;

    // validate arguments

    if (WRITE_ACCESS != access  || vmm_acpi_pm_port_size() != port_size) {
        goto pass_transparently;
    }

    if (port_id == pm_port[ACPI_PM1_CNTRL_REG_A]) {
        pm_reg_id = ACPI_PM1_CNTRL_REG_A;
    }
    else if (port_id == pm_port[ACPI_PM1_CNTRL_REG_B]) {
        pm_reg_id = ACPI_PM1_CNTRL_REG_B;
    }
    else {
        goto pass_transparently;
    }

    switch (port_size) {
    case 2:
        value = *(UINT16 *) p_value;
        break;
    case 4:
        value = *(UINT32 *) p_value;
        break;
    default:
        goto pass_transparently;
    }

    sleep_state = vmm_acpi_sleep_type_to_state(pm_reg_id, SLP_TYP(value));
    sleep_enable = SLP_EN(value);

    // System enters sleep state only if "sleep enable" bit is set
    if(sleep_enable) {
        VMM_LOG(mask_anonymous, level_trace,"[ACPI] SleepState(%d) requested at pm_reg_id(%c) port_id(%P) port_size(%d) access(%d)\n",
                sleep_state, pm_reg_id + 'A', port_id, port_size, access);

        switch (sleep_state) {
            case 1:
                break;
            case 2:
                break;
            case 3: // standby
                if (VMM_OK != vmm_acpi_prepare_for_s3(gcpu)) {
                    VMM_LOG(mask_anonymous, level_error,"[acpi] vmm_acpi_prepare_for_s3() failed\n");
                }
                break;
            case 4: // hibernate
                break;
            case 5: // shutdown
                break;
            default:
                break;
            }
    }

pass_transparently:
    io_vmexit_transparent_handler(gcpu, port_id, port_size, access, p_value, NULL);
    return TRUE;
}



#pragma warning( push )
#pragma warning( disable : 4100 )

void vmm_acpi_prepare_cpu_for_s3(CPU_ID from UNUSED, void *unused UNUSED)
{
    GUEST_CPU_HANDLE        gcpu;
    SCHEDULER_GCPU_ITERATOR iterator;
    CPU_ID                  cpu_id = hw_cpu_id();

    VMM_LOG(mask_anonymous, level_trace,"[ACPI] CPU(%d) going to go to S3\n", cpu_id);

	vmm_startup_data.cpu_local_apic_ids[hw_cpu_id()] = local_apic_get_current_id();

    // deactivate active gcpu
    gcpu = scheduler_current_gcpu();
    VMM_ASSERT(gcpu);

    SET_CACHED_ACTIVITY_STATE(gcpu, Ia32VmxVmcsGuestSleepStateWaitForSipi);

	report_uvmm_event(UVMM_EVENT_SINGLE_STEPPING_CHECK, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL);

    gcpu_swap_out(gcpu);

    // for all GCPUs on this CPU do:
    for (gcpu = scheduler_same_host_cpu_gcpu_first(&iterator, cpu_id);
         gcpu != NULL; gcpu = scheduler_same_host_cpu_gcpu_next(&iterator)) {
        VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);
        VMM_ASSERT(vmcs);

        // Clear VMCS
        vmcs_flush_to_memory(vmcs);

        event_raise(EVENT_GCPU_ENTERING_S3, gcpu, NULL);
    }

    // Turn VMX Off
    vmcs_hw_vmx_off();

    hw_interlocked_increment(&number_of_stopped_cpus); // indicate that CPU is down

    // Invalidate caches
    hw_wbinvd();

    if (0 != cpu_id) {
        hw_halt(); // halt
    }
}
#pragma warning( pop )


#pragma warning( push )
#pragma warning( disable : 4100 )

VMM_STATUS vmm_acpi_prepare_for_s3(GUEST_CPU_HANDLE gcpu UNUSED)
{
    UINT32 waking_vector;
    UINT64 extended_waking_vector;
    void *p_waking_vector;
    IPC_DESTINATION ipc_dest;

    // 1. Get original waking vector code
    if (0 != vmm_acpi_waking_vector(&waking_vector, &extended_waking_vector) ||
        (0 == waking_vector && 0 == extended_waking_vector)) {
        VMM_LOG(mask_anonymous, level_trace,"[ACPI] Waking Vector is NULL. S3 is not supported by the platform\n");
        return VMM_ERROR;
    }

    vmm_memset( &ipc_dest, 0, sizeof( ipc_dest ));
    number_of_started_cpus = 0;
    number_of_stopped_cpus = 0;


    // 2. Force other CPUs and itself to prepare for S3
    ipc_dest.addr_shorthand = IPI_DST_ALL_EXCLUDING_SELF;
    ipc_execute_handler(ipc_dest, vmm_acpi_prepare_cpu_for_s3, NULL);

    vmm_acpi_prepare_cpu_for_s3(0, NULL);


    // 3. perform some vtlb-related actions
    //TBD::

    // 4. Prepare INIT64_STRUCT data
    vmm_acpi_prepare_init64_data();


    //    5. Store original waking vector content aside
    //    Notice that we reuse the same low memory page 3 times
    //    once for BSP transition to protected mode, second time for AP initialization,
    //    and finally for guest original purpose.
    //    Replace it with VMM startup code
    //    Patch VMM start up code with running environment values


    if (0 != extended_waking_vector) {
        // save original code
        p_waking_vector = (void *) extended_waking_vector;
        vmm_acpi_save_original_waking_code(p_waking_vector);

        // Prepare INIT32_STRUCT data.
        vmm_acpi_prepare_init32_data((UINT32)extended_waking_vector);

        vmm_acpi_build_s3_resume_protected_layout(p_waking_vector);
    }
    else {
        // save original code
        p_waking_vector = (void *) (size_t) waking_vector;
        vmm_acpi_save_original_waking_code(p_waking_vector);

        // Prepare INIT32_STRUCT data.
        vmm_acpi_prepare_init32_data(waking_vector);

        vmm_acpi_build_s3_resume_real_mode_layout(waking_vector);

        // Do not dump for release build.
        // dump_s3_resume_real_mode_code((VMM_S3_REAL_MODE_RESUME_LAYOUT *)(size_t)waking_vector);
    }

    // wait while all APs are down too
    WAIT_FOR_MP_CONDITION(number_of_stopped_cpus == vmm_startup_data.number_of_processors_at_boot_time);

    // 6. Invalidate caches
    hw_wbinvd();

    vmm_acpi_notify_on_platform_suspend();

    return VMM_OK;
}
#pragma warning( pop )


void vmm_acpi_prepare_init64_data(void)
{
    EM64T_GDTR gdtr_64;

    hw_sgdt(&gdtr_64);
    init64_data.i64_gdtr.base = (UINT32) gdtr_64.base;
    init64_data.i64_gdtr.limit = gdtr_64.limit;
    init64_data.i64_cr3 = (UINT32) hw_read_cr3();
    init64_data.i64_cs  = hw_read_cs();
    init64_data.i64_efer = hw_read_msr(IA32_MSR_EFER) & EFER_NXE;

    VMM_LOG(mask_anonymous, level_trace,"Init64 Data\n");
    VMM_LOG(mask_anonymous, level_trace,"i64_gdtr.base    =%P\n", init64_data.i64_gdtr.base);
    VMM_LOG(mask_anonymous, level_trace,"i64_gdtr.limit   =%P\n", init64_data.i64_gdtr.limit);
    VMM_LOG(mask_anonymous, level_trace,"i64_gdtr.i64_cr3 =%P\n", init64_data.i64_cr3);
    VMM_LOG(mask_anonymous, level_trace,"i64_gdtr.i64_cs  =%P\n", init64_data.i64_cs);
    VMM_LOG(mask_anonymous, level_trace,"i64_gdtr.i64_efer=%P\n",init64_data.i64_efer);

}

void setup_data_for_s3(void)
{
#define ASK_ALL_MEMORY_HOLDERS (UINT32) -1

    if (vmm_startup_data.number_of_processors_at_boot_time > 1){
        if(!init32_data_p) {
            UINT16 num_of_aps = vmm_startup_data.number_of_processors_at_boot_time - 1;
            init32_data_p = vmm_memory_alloc_must_succeed(
                ASK_ALL_MEMORY_HOLDERS,
                sizeof(INIT32_STRUCT) + num_of_aps * sizeof(UINT32));
         }
    }
}


void vmm_acpi_prepare_init32_data(UINT32 low_memory_page_address)
{

    // if there are Application Processors
    if (vmm_startup_data.number_of_processors_at_boot_time > 1) {
        UINT16 i;
        UINT16 num_of_aps = vmm_startup_data.number_of_processors_at_boot_time - 1;
        
        VMM_ASSERT(low_memory_page_address);
        VMM_ASSERT(init32_data_p);

        init32_data_p->i32_low_memory_page = low_memory_page_address;
        init32_data_p->i32_num_of_aps      = num_of_aps;

        for (i = 0; i < num_of_aps; ++i) {
            HVA stack_pointer;
            BOOLEAN success = vmm_stack_get_stack_pointer_for_cpu(i + 1, &stack_pointer);
            if (! success) {
                VMM_LOG(mask_anonymous, level_trace,"[acpi] Failed to allocate stacks for APs. Run as a single core\n");
                vmm_memory_free(init32_data_p);
                init32_data_p = NULL;
                return;
            }
            init32_data_p->i32_esp[i] = (UINT32) stack_pointer - 512;
        }
    }
}

#pragma warning( push )
#pragma warning( disable : 4100 )

void CDECL vmm_acpi_resume_after_s3_c_main(
    UINT32 cpu_id,
    UINT64 startup_struct_u UNUSED,
    UINT64 application_params_struct_u UNUSED,
    UINT64 reserved UNUSED)
{
    GUEST_CPU_HANDLE initial_gcpu;
    EPT_GUEST_STATE *ept_guest = NULL;
    EPT_GUEST_CPU_STATE *ept_guest_cpu = NULL;
    const VIRTUAL_CPU_ID* vcpu_id = NULL;

    g_s3_resume_flag = 1;
    vmm_debug_port_clear();
    vmm_io_init();

    // hw_gdt_load must be called before VMM_LOG,
    // otherwise it will decide that emulator_is_running_as_guest()
    hw_gdt_load((CPU_ID)cpu_id);

    VMM_LOG(mask_anonymous, level_trace,"\n******************************************\n");
    VMM_LOG(mask_anonymous, level_trace,"\n\nSystem Resumed after S3 on CPU(%d)\n\n", cpu_id);
    VMM_LOG(mask_anonymous, level_trace,"\n******************************************\n");

    isr_handling_start();

    hmm_set_required_values_to_control_registers();

    // init CR0/CR4 to the VMX compatible values
    hw_write_cr0(  vmcs_hw_make_compliant_cr0( hw_read_cr0() ) );
    hw_write_cr4(  vmcs_hw_make_compliant_cr4( hw_read_cr4() ) );

    host_cpu_enable_usage_of_xmm_regs();

    // init current host CPU
    host_cpu_init();

    // assume the Local APIC host base won't be changed by BIOS.
    update_lapic_cpu_id();

    vmm_acpi_notify_on_platform_resume();

    vmcs_hw_vmx_on();
    VMM_LOG(mask_anonymous, level_trace,"CPU%d: VMXON\n", cpu_id);

    // schedule first gcpu
    initial_gcpu = scheduler_select_initial_gcpu();

    VMM_ASSERT( initial_gcpu != NULL );
    VMM_LOG(mask_anonymous, level_trace,"CPU%d: initial guest selected: GUEST_ID: %d GUEST_CPU_ID: %d\n",
              cpu_id,
              guest_vcpu( initial_gcpu )->guest_id,
              guest_vcpu( initial_gcpu )->guest_cpu_id );

    vcpu_id = guest_vcpu( initial_gcpu );
    ept_guest = ept_find_guest_state(vcpu_id->guest_id);
    VMM_ASSERT(ept_guest);
    ept_guest_cpu = ept_guest->gcpu_state[vcpu_id->guest_cpu_id];

    if (0 == cpu_id)    //--------- BSP
    {
        vmm_acpi_restore_original_waking_code();

        // fill s3_resume_bsp_gcpu_initial_state
        vmm_acpi_fill_bsp_gcpu_initial_state(initial_gcpu);

        gcpu_initialize(initial_gcpu, &s3_resume_bsp_gcpu_initial_state);

        // Set ept_guest_cpu->cr0 for BSP to synchronize with guest visible CR0
        ept_guest_cpu->cr0 = gcpu_get_guest_visible_control_reg(initial_gcpu, IA32_CTRL_CR0);
        ept_guest_cpu->cr4 = gcpu_get_guest_visible_control_reg(initial_gcpu, IA32_CTRL_CR4);

        hw_interlocked_increment(&number_of_started_cpus); // indicate that CPU is up

        // wait while all APs are up too
        WAIT_FOR_MP_CONDITION(number_of_started_cpus == vmm_startup_data.number_of_processors_at_boot_time);
    }
    else                //--------- AP
    {
        gcpu_set_activity_state(initial_gcpu, Ia32VmxVmcsGuestSleepStateWaitForSipi);
        // indicate that CPU is up
        hw_interlocked_increment(&number_of_started_cpus);
    }

    event_raise(EVENT_GCPU_RETURNED_FROM_S3, initial_gcpu, NULL);

    gcpu_resume( initial_gcpu );

    VMM_DEADLOOP();

}
#pragma warning( pop )

BOOLEAN vmm_acpi_register_platform_suspend_callback(vmm_acpi_callback suspend_cb)
{
    static int available_index = 0;

    if(available_index >= MAX_ACPI_CALLBACKS) {
        VMM_LOG(mask_anonymous, level_trace,"acpi-pm: too many registrations for suspend callback\r\n");
        return FALSE;
    }
    suspend_callbacks[available_index++] = suspend_cb;
    return TRUE;
}

static void vmm_acpi_notify_on_platform_suspend(void)
{
    int i;

    for(i = 0; i < MAX_ACPI_CALLBACKS; i++) {
        if(NULL != suspend_callbacks[i]) {
            suspend_callbacks[i]();
        }
    }
}

BOOLEAN vmm_acpi_register_platform_resume_callback(vmm_acpi_callback resume_cb)
{
    static int available_index = 0;

    if(available_index >= MAX_ACPI_CALLBACKS) {
        VMM_LOG(mask_anonymous, level_trace,"acpi-pm: too many registrations for resume callback\r\n");
        return FALSE;
    }
    resume_callbacks[available_index++] = resume_cb;
    return TRUE;
}

static void vmm_acpi_notify_on_platform_resume(void)
{
    int i;

    for(i = 0; i < MAX_ACPI_CALLBACKS; i++) {
        if(NULL != resume_callbacks[i]) {
            resume_callbacks[i]();
        }
    }
}

//
// This function assumes that waking vector was called in Real Mode
//
void vmm_acpi_fill_bsp_gcpu_initial_state(GUEST_CPU_HANDLE gcpu)
{
    UINT64 offset = (UINT64) vmm_waking_vector - (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.cs);

    s3_resume_bsp_gcpu_initial_state.size_of_this_struct                 = sizeof(s3_resume_bsp_gcpu_initial_state);
    s3_resume_bsp_gcpu_initial_state.version_of_this_struct              = 0x01;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RAX]                = cpu_saved_state.eax;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RBX]                = cpu_saved_state.ebx;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RCX]                = cpu_saved_state.ecx;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RDX]                = cpu_saved_state.edx;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RDI]                = cpu_saved_state.edi;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RSI]                = cpu_saved_state.esi;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RBP]                = cpu_saved_state.ebp;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RSP]                = cpu_saved_state.esp;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RIP]                = offset;
    s3_resume_bsp_gcpu_initial_state.gp.reg[IA32_REG_RFLAGS]             = cpu_saved_state.eflags;

    // The attributes of CS,DS,SS,ES,FS,GS,LDTR and TR are set based on
    // Volume 3B, System Programming Guide, section 23.3.1.2
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_CS].selector   = cpu_saved_state.cs;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_CS].limit      = 0x0000FFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_CS].attributes = 0x9b;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_CS].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.cs);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_DS].selector   = cpu_saved_state.ds;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_DS].limit      = 0xFFFFFFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_DS].attributes = 0x8091;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_DS].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.ds);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_SS].selector   = cpu_saved_state.ss;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_SS].limit      = 0xFFFFFFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_SS].attributes = 0x8093;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_SS].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.ss);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_ES].selector   = cpu_saved_state.es;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_ES].limit      = 0xFFFFFFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_ES].attributes = 0x8093;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_ES].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.es);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_FS].selector   = cpu_saved_state.fs;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_FS].limit      = 0xFFFFFFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_FS].attributes = 0x8091;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_FS].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.fs);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_GS].selector   = cpu_saved_state.gs;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_GS].limit      = 0xFFFFFFFF;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_GS].attributes = 0x8091;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_GS].base       =
        (UINT64) REALMODE_SEGMENT_SELECTOR_TO_BASE(cpu_saved_state.gs);

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_LDTR].base     = 0;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_LDTR].limit    = 0;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_LDTR].attributes =0x10000;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_LDTR].selector = 0;

    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_TR].base       = 0;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_TR].limit      = 0;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_TR].attributes = 0x8b;
    s3_resume_bsp_gcpu_initial_state.seg.segment[IA32_SEG_TR].selector   = 0;

    s3_resume_bsp_gcpu_initial_state.control.cr[IA32_CTRL_CR0]           = 0x00000010;
    s3_resume_bsp_gcpu_initial_state.control.cr[IA32_CTRL_CR2]           = 0;
    s3_resume_bsp_gcpu_initial_state.control.cr[IA32_CTRL_CR3]           = 0;
    s3_resume_bsp_gcpu_initial_state.control.cr[IA32_CTRL_CR4]           = 0x00000050;

    s3_resume_bsp_gcpu_initial_state.control.gdtr.base                   = cpu_saved_state.gdtr.base;
    s3_resume_bsp_gcpu_initial_state.control.gdtr.limit                  = cpu_saved_state.gdtr.limit;

    s3_resume_bsp_gcpu_initial_state.control.idtr.base                   = cpu_saved_state.idtr.base;
    s3_resume_bsp_gcpu_initial_state.control.idtr.limit                  = cpu_saved_state.idtr.limit;

    s3_resume_bsp_gcpu_initial_state.msr.msr_debugctl                    = 0x00000001;
    s3_resume_bsp_gcpu_initial_state.msr.msr_efer                        = 0;
    s3_resume_bsp_gcpu_initial_state.msr.msr_pat                         = gcpu_get_msr_reg(gcpu,IA32_VMM_MSR_PAT);
    s3_resume_bsp_gcpu_initial_state.msr.msr_sysenter_esp                = 0;
    s3_resume_bsp_gcpu_initial_state.msr.msr_sysenter_eip                = 0;
    s3_resume_bsp_gcpu_initial_state.msr.pending_exceptions              = 0;
    s3_resume_bsp_gcpu_initial_state.msr.msr_sysenter_cs                 = 0;
    s3_resume_bsp_gcpu_initial_state.msr.interruptibility_state          = 0;
    s3_resume_bsp_gcpu_initial_state.msr.activity_state                  = 0;
    s3_resume_bsp_gcpu_initial_state.msr.smbase                          = 0;

}


#endif
