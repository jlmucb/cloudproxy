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


// Perform application processors init
#include "bootstrap_types.h"
#include "vmm_defs.h"
#include "vmm_startup.h"
#include "bootstrap_ap_procs_init.h"
#include "bootstrap_print.h"
#include "common_libc.h"
#include "ia32_defs.h"
#include "x32_init64.h"
#include "em64t_defs.h"


#define JLMDEBUG


// AP startup algorithm
//  Stage 1
//   BSP:
//      1. Copy APStartUpCode + GDT to low memory page
//      2. Clear APs counter
//      3. Send SIPI to all processors excluding self
//      4. Wait timeout
//   APs on SIPI receive:
//      1. Switch to protected mode
//      2. lock inc APs counter + remember my AP number
//      3. Loop on wait_lock1 until it changes zero
// Stage 2
//   BSP after timeout:
//      5. Read number of APs and allocate memory for stacks
//      6. Save GDT and IDT in global array
//      7. Clear ready_counter count
//      8. Set wait_lock1 to 1
//      9. Loop on ready_counter until it will be equal to number of APs
//   APs on wait_1_lock set
//      4. Set stack in a right way
//      5. Set right GDT and IDT
//      6. Enter "C" code
//      7. Increment ready_counter
//      8. Loop on wait_lock2 until it changes from zero
// Stage 3
//   BSP after ready_counter becomes == APs number
//      10. Return to user
// PROBLEM:
//   NMI may crash the system if it comes before AP stack init done


#define IA32_DEBUG_IO_PORT   0x80
#define INITIAL_WAIT_FOR_APS_TIMEOUT_IN_MILIS 150000

void send_init_ipi(void);
void send_broadcast_init_sipi(INIT32_STRUCT *p_init32_data);
void send_ipi_to_all_excluding_self(uint32_t vector_number, 
              uint32_t delivery_mode);

extern uint32_t startap_rdtsc();
extern void ia32_read_msr(uint32_t msr_id, uint64_t *p_value);
static uint32_t startap_tsc_ticks_per_msec = 0;


typedef enum {
    MP_BOOTSTRAP_STATE_INIT = 0,
    MP_BOOTSTRAP_STATE_APS_ENUMERATED = 1,
} MP_BOOTSTRAP_STATE;

static volatile MP_BOOTSTRAP_STATE mp_bootstrap_state;

// stage 1
static uint32_t  g_aps_counter = 0;

// stage 2
static uint8_t   gp_GDT[6] = {0};  // xx:xxxx
static uint8_t   gp_IDT[6] = {0};  // xx:xxxx

static volatile uint32_t        g_ready_counter = 0;
static FUNC_CONTINUE_AP_BOOT    g_user_func = 0;
static void*                    g_any_data_for_user_func = 0;

// 1 in i position means CPU[i] exists
static uint8_t ap_presence_array[VMM_MAX_CPU_SUPPORTED] = {0};  
extern uint32_t evmm_stack_pointers_array[];


// Low memory page layout
//   APStartUpCode
//   GdtTable

// Uncomment the following line to deadloop in AP startup
#define BREAK_IN_AP_STARTUP
const uint8_t APStartUpCode[] =
{
#ifdef BREAK_IN_AP_STARTUP
    0xEB, 0xFE,                    // jmp $
#endif
    0xB8, 0x00, 0x00,              // 00: mov  ax,AP_START_UP_SEGMENT
    0x8E, 0xD8,                    // 03: mov  ds,ax
    0x8D, 0x36, 0x00, 0x00,        // 05: lea  si,GDTR_OFFSET_IN_PAGE
    0x0F, 0x01, 0x14,              // 09: lgdt fword ptr [si]
    0x0F, 0x20, 0xC0,              // 12: mov  eax,cr0
    0x0C, 0x01,                    // 15: or   al,1
    0x0F, 0x22, 0xC0,              // 17: mov  cr0,eax
    0x66, 0xEA,                    // 20: fjmp CS,CONT16
    0x00, 0x00, 0x00, 0x00,        // 22:   CONT16
    0x00, 0x00,                    // 26:   CS_VALUE
//CONT16:
    0xFA,                          // 28: cli
    0x66, 0xB8, 0x00, 0x00,        // 29: mov  ax,DS_VALUE
    0x66, 0x8E, 0xD8,              // 33: mov  ds,ax
    0x66, 0xB8, 0x00, 0x00,        // 36: mov  ax,ES_VALUE
    0x66, 0x8E, 0xC0,              // 40: mov  es,ax
    0x66, 0xB8, 0x00, 0x00,        // 43: mov  ax,GS_VALUE
    0x66, 0x8E, 0xE8,              // 47: mov  gs,ax
    0x66, 0xB8, 0x00, 0x00,        // 50: mov  ax,FS_VALUE
    0x66, 0x8E, 0xE0,              // 54: mov  fs,ax
    0x66, 0xB8, 0x00, 0x00,        // 57: mov  ax,SS_VALUE
    0x66, 0x8E, 0xD0,              // 61: mov  ss,ax
    0xB8, 0x00, 0x00, 0x00, 0x00,  // 64: mov  eax,AP_CONTINUE_WAKEUP_CODE
    0xFF, 0xE0,                    // 69: jmp  eax
    ////    0x00                   // 71: 32 bytes alignment
};

#ifdef BREAK_IN_AP_STARTUP
#define AP_CODE_START                           2
#else
#define AP_CODE_START                           0
#endif

#define AP_START_UP_SEGMENT_IN_CODE_OFFSET      (1 + AP_CODE_START)
#define GDTR_OFFSET_IN_CODE                     (7 + AP_CODE_START)
#define CONT16_IN_CODE_OFFSET                   (22 + AP_CODE_START)
#define CONT16_VALUE_OFFSET                     (28 + AP_CODE_START)
#define CS_IN_CODE_OFFSET                       (26 + AP_CODE_START)
#define DS_IN_CODE_OFFSET                       (31 + AP_CODE_START)
#define ES_IN_CODE_OFFSET                       (38 + AP_CODE_START)
#define GS_IN_CODE_OFFSET                       (45 + AP_CODE_START)
#define FS_IN_CODE_OFFSET                       (52 + AP_CODE_START)
#define SS_IN_CODE_OFFSET                       (59 + AP_CODE_START)

#define AP_CONTINUE_WAKEUP_CODE_IN_CODE_OFFSET  (65 + AP_CODE_START)

#define GDTR_OFFSET_IN_PAGE  ((sizeof(APStartUpCode) + 7) & ~7)
#define GDT_OFFSET_IN_PAGE   (GDTR_OFFSET_IN_PAGE + 8)

void     ap_continue_wakeup_code(void);
void     ap_continue_wakeup_code_C(uint32_t local_apic_id);
uint8_t  bsp_enumerate_aps(void);
void     ap_initialize_environment(void);
void     mp_set_bootstrap_state(MP_BOOTSTRAP_STATE new_state);


// Setup AP low memory startup code
void setup_low_memory_ap_code(uint32_t temp_low_memory_4K)
{
    uint8_t*    code_to_patch = (uint8_t*)temp_low_memory_4K;
    IA32_GDTR   gdtr_32;
    UINT16      cs_value;
    UINT16      ds_value;
    UINT16      es_value;
    UINT16      gs_value;
    UINT16      fs_value;
    UINT16      ss_value;
    extern IA32_GDTR*      p_tboot_gdtr;
    extern uint16_t        tboot_cs_selector;
    extern uint16_t        tboot_ds_selector;
    extern uint16_t        tboot_ss_selector;

#ifdef JLMDEBUG
    bprint("setup_low_memory\n");
#endif
    // Copy the Startup code to the beginning of the page
    vmm_memcpy(code_to_patch, (const void*)APStartUpCode, sizeof(APStartUpCode));

    // get current segments
#if 0
    __asm__ volatile (
        "\tmovw %%cs, %[cs_value]\n"
        "\tmovw %%ds, %[ds_value]\n"
        "\tmovw %%es, %[es_value]\n"
        "\tmovw %%gs, %[gs_value]\n"
        "\tmovw %%fs, %[fs_value]\n"
        "\tmovw %%ss, %[ss_value]\n"
    : [cs_value] "=m" (cs_value), [ds_value] "=m" (ds_value), 
      [es_value] "=m" (es_value), [gs_value] "=m" (gs_value), 
      [fs_value] "=m" (fs_value), [ss_value] "=m" (ss_value)
    ::);
#else
    cs_value= tboot_cs_selector;
    ds_value= tboot_ds_selector;
    es_value= tboot_ds_selector;
    gs_value= tboot_ds_selector;
    fs_value= tboot_ds_selector;
    ss_value= tboot_ss_selector;
#endif

    // Patch the startup code
    *((UINT16*)(code_to_patch + AP_START_UP_SEGMENT_IN_CODE_OFFSET)) =
                                    (UINT16)(temp_low_memory_4K >> 4);
    *((UINT16*)(code_to_patch + GDTR_OFFSET_IN_CODE)) =
                                    (UINT16)(GDTR_OFFSET_IN_PAGE);
    *((uint32_t*)(code_to_patch+CONT16_IN_CODE_OFFSET)) =
                                   (uint32_t)code_to_patch + CONT16_VALUE_OFFSET;
    *((UINT16*)(code_to_patch + CS_IN_CODE_OFFSET)) = cs_value;
    *((UINT16*)(code_to_patch + DS_IN_CODE_OFFSET)) = ds_value;
    *((UINT16*)(code_to_patch + ES_IN_CODE_OFFSET)) = es_value;
    *((UINT16*)(code_to_patch + GS_IN_CODE_OFFSET)) = gs_value;
    *((UINT16*)(code_to_patch + FS_IN_CODE_OFFSET)) = fs_value;
    *((UINT16*)(code_to_patch + SS_IN_CODE_OFFSET)) = ss_value;
    *((uint32_t*)(code_to_patch + AP_CONTINUE_WAKEUP_CODE_IN_CODE_OFFSET)) =
                                            (uint32_t)(ap_continue_wakeup_code);

    // get GDTR from BSP
    extern void  ia32_read_gdtr(IA32_GDTR *p_descriptor);
    ia32_read_gdtr(&gdtr_32);

    // copy GDT 
    vmm_memcpy(code_to_patch+GDT_OFFSET_IN_PAGE,
               (uint8_t*)gdtr_32.base, gdtr_32.limit+1);

#ifdef JLMDEBUG
    extern void HexDump(uint8_t*, uint8_t*);
    bprint("patched code, gdtr base: 0x%08x, limit: %d\n", 
           p_tboot_gdtr->base, p_tboot_gdtr->limit);
    HexDump((uint8_t*)p_tboot_gdtr->base, 
            (uint8_t*)p_tboot_gdtr->base+p_tboot_gdtr->limit);
    bprint("cs_value: 0x%04x\n", cs_value);
    bprint("patched code\n");
    HexDump(code_to_patch, code_to_patch+sizeof(APStartUpCode));
    LOOP_FOREVER
#endif
// what is this for?
#if 0    
    IA32_GDTR*  new_gdtr_32;
    // Patch the GDT base address in memory
    new_gdtr_32 = (IA32_GDTR *)(code_to_patch+GDTR_OFFSET_IN_PAGE);
    new_gdtr_32->base = (uint32_t)code_to_patch+GDT_OFFSET_IN_PAGE;
#endif
    return;
}


// Initial AP setup in protected mode - should never return
void ap_continue_wakeup_code_C(uint32_t local_apic_id)
{
#ifdef JLMDEBUG
    bprint("ap_continue_wakeup_code_C %d\n", local_apic_id);
    LOOP_FOREVER
#endif
    // mark that the command was accepted
    __asm__ volatile (
        "\tlock; incl %[g_ready_counter]\n"
    : [g_ready_counter] "=m" (g_ready_counter)
    ::);

    // user_func now contains address of the function to be called
    g_user_func(local_apic_id, g_any_data_for_user_func);
    return;
}

#if 0
// Asm-level initial AP setup in protected mode
void ap_continue_wakeup_code(void)
{
    __asm__ volatile (
        "\tcli\n"
        // get the Local APIC ID
        // IA32_MSR_APIC_BASE= 0x01B
        "\tmovl  $0x01B, %%ecx\n"
        "\trdmsr\n"
        // LOCAL_APIC_BASE_MSR_MASK= $0xfffff000
        "\tandl $0xfffff000, %%eax\n"
        // LOCAL_APIC_IDENTIFICATION_OFFSET= 0x20
        "\tmovl 0x20(%%eax), %%ecx\n"
        // LOCAL_APIC_ID_LOW_RESERVED_BITS_COUNT= 24
        "\tshrl $24, %%ecx\n"

        // edx <- address of presence array
        "\tleal (%[ap_presence_array]), %%edx\n"
        // edx <- address of AP CPU presence location
        "\taddl %%ecx, %%edx\n"
        // mark current CPU as present
        "\tmovl $1, (%%edx)\n"
        // wait until BSP will init stacks, GDT, IDT, etc
"1:\n"
        // MP_BOOTSTRAP_STATE_APS_ENUMERATED= 1
        "\tcmpl $1, %[mp_bootstrap_state]\n"
        "\tje 2f\n"
        "\tpause\n"
        "\tjmp 1b\n"

        // stage 2 - setup the stack, GDT, IDT and jump to "C"
"2:\n"
        // find my stack. My stack offset is in the array 
        // edx contains CPU ID
        "\txorl %%ecx,  %%ecx\n"
        // now ecx contains AP ordered ID [1..Max]
        "\tmovb (%%edx), %%cl\n"
        "\tmovl %%ecx, %%eax\n"
        //  AP starts from 1, so subtract one to get proper index in g_stacks_arr
        "\tdecl %%eax\n"

        // point edx to right stack
        "\tmovl %[evmm_stack_pointers_array], %%edx\n"
        "\tleal (%%eax, %%edx, 4), %%eax\n"
        "\tmovl (%%edx), %%esp\n"

        // setup GDT
        "\tmovl %[gp_GDT], %%eax\n"
        "\tlgdt (%%eax) \n"

        // setup IDT
        "\tmovl %[gp_IDT], %%eax\n"
        "\tlidt (%%eax)\n"

        // enter "C" function
        // JLM(FIX): this seems wrong
        //  %ecx is an arg to C function
        //  push  AP ordered ID
        // "\tpushl    %%ecx\n"
        "\tmovl    %%ecx, %%edi\n"

        // should never return
        "\tcall  ap_continue_wakeup_code_C\n"
    : 
    : [ap_continue_wakeup_code_C] "g" (ap_continue_wakeup_code_C),
      [mp_bootstrap_state] "g" (mp_bootstrap_state),
      [ap_presence_array] "r" (ap_presence_array),
      [evmm_stack_pointers_array] "p" (evmm_stack_pointers_array),
      [gp_GDT] "g" (gp_GDT), [gp_IDT] "g" (gp_IDT)
    :"%eax", "%ebx", "%ecx", "%edx", "memory");
}
#else
__asm__(
".text\n"
".globl ap_continue_wakeup_code\n"
".type ap_continue_wakeup_code,@function\n"
"ap_continue_wakeup_code:\n"
        "\tcli\n"
// DEBUG
//        "\tjmp .\n"
// DEBUG
        // get the Local APIC ID
        // IA32_MSR_APIC_BASE= 0x01B
        "\tmov  $0x01B, %ecx\n"
        "\trdmsr\n"
        // LOCAL_APIC_BASE_MSR_MASK= $0xfffff000
        "\tand   $0xfffff000, %eax\n"
        // LOCAL_APIC_IDENTIFICATION_OFFSET= 0x20
        "\tmov   0x20(%eax), %ecx\n"
        // LOCAL_APIC_ID_LOW_RESERVED_BITS_COUNT= 24
        "\tshr   $24, %ecx\n"

        // edx <- address of presence array
        "\tlea   ap_presence_array, %edx\n"
        // edx <- address of AP CPU presence location
        "\tadd   %ecx, %edx\n"
        // mark current CPU as present
        "\tmovl  $1, (%edx)\n"
        // wait until BSP will init stacks, GDT, IDT, etc
"1:\n"
        // MP_BOOTSTRAP_STATE_APS_ENUMERATED= 1
        "\tcmpl  $1, mp_bootstrap_state\n"
        "\tje    2f\n"
        "\tpause\n"
        "\tjmp   1b\n"

        // stage 2 - setup the stack, GDT, IDT and jump to "C"
"2:\n"
        // find my stack. My stack offset is in the array 
        // edx contains CPU ID
        "\txor   %ecx,  %ecx\n"
        // now ecx contains AP ordered ID [1..Max]
        "\tmovb  (%edx), %cl\n"
        "\tmov   %ecx, %eax\n"
        //  AP starts from 1, so subtract one to get proper index in g_stacks_arr
        "\tdec   %eax\n"

        // point edx to right stack
        "\tmov   evmm_stack_pointers_array, %edx\n"
        "\tlea   (%eax, %edx, 4), %eax\n"
        "\tmov   (%edx), %esp\n"

        // setup GDT
        "\tmov   gp_GDT, %eax\n"
        "\tlgdt  (%eax) \n"

        // setup IDT
        "\tmov   gp_IDT, %eax\n"
        "\tlidt (%eax)\n"

        // enter "C" function
        //  push  AP ordered ID
        "\tmov    %ecx, %edi\n"
        // should never return
        "\tcall  ap_continue_wakeup_code_C\n"
);
#endif


static uint8_t read_port_8(uint32_t port)
{
    uint8_t out;
    __asm__ volatile (
        "\tlock; incl %[g_ready_counter]\n"
        "\tmovl %[port],%%edx\n"
        "\txorl %%eax, %%eax\n"
        "\tin   %%dx, %%al\n"
        "\tmovb %%al, %[out]\n"
    : [g_ready_counter] "=m" (g_ready_counter), [out] "=m" (out)
    : [port] "m" (port)
    :"%edx", "%eax");
    return out;
}


// Stall (busy loop) for a given time, using the platform's speaker port
// h/w.  Should only be called at initialization, since a guest OS may
// change the platform setting.
void startap_stall(uint32_t stall_usec)
{
    uint32_t   c = 0;
    for(c= 0; c<stall_usec; c++)
        read_port_8(IA32_DEBUG_IO_PORT);
    return;
}


// Calibrate the internal variable with number of TSC ticks pers second.
// Should only be called at initialization, as it relies on startap_stall()
void startap_calibrate_tsc_ticks_per_msec(void)
{
    uint32_t start_tsc = 1, end_tsc = 0;

    while(start_tsc>end_tsc) {
        start_tsc= (uint32_t) startap_rdtsc();
        startap_stall(1000);   // 1 ms
        end_tsc= (uint32_t) startap_rdtsc();
    }
    startap_tsc_ticks_per_msec= (end_tsc-start_tsc);
    return;
}


// Stall (busy loop) for a given time, using the CPU TSC register.
// Note that, depending on the CPU and ASCI modes, the stall accuracy 
// may be rough.
void startap_stall_using_tsc(uint32_t stall_usec)
{
    uint32_t   start_tsc = 1, end_tsc = 0;

    // Initialize startap_tsc_ticks_per_msec. Happens at boot time
    if(startap_tsc_ticks_per_msec == 0) {
        startap_calibrate_tsc_ticks_per_msec();
    }
    // Calculate the start_tsc and end_tsc
    // While loop is to overcome the overflow of 32-bit rdtsc value
        while(start_tsc > end_tsc) {
            end_tsc = (uint32_t) startap_rdtsc() + 
                        (stall_usec*startap_tsc_ticks_per_msec/1000);
                start_tsc = (uint32_t) startap_rdtsc();
        }
    while (start_tsc < end_tsc) {
        __asm__ volatile (
            "\tpause\n"
        :::);
        start_tsc = (uint32_t) startap_rdtsc();
    }
    return;
}


void send_ipi_to_specific_cpu (uint32_t vector_number, 
                            uint32_t delivery_mode, uint8_t dst)
{
    IA32_ICR_LOW           icr_low;
    IA32_ICR_LOW           icr_low_status;
    IA32_ICR_HIGH          icr_high;
    UINT64                 apic_base = 0;

#ifdef JLMDEBUG
    bprint("send_ipi_to_specific_cpu (%d, %d, %d)\n",
                 vector_number, delivery_mode, dst);
#endif
    vmm_memset(&icr_low, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_low_status, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_high, 0, sizeof(IA32_ICR_HIGH));
    icr_low.bits.vector= vector_number;
    icr_low.bits.delivery_mode = delivery_mode;

    //    level is set to 1 (except for INIT_DEASSERT)
    //    trigger mode is set to 0 (except for INIT_DEASSERT)
    icr_low.bits.level = 1;
    icr_low.bits.trigger_mode = 0;

    // send to specific cpu
    icr_low.bits.destination_shorthand = LOCAL_APIC_BROADCAST_MODE_SPECIFY_CPU;
    icr_high.bits.destination = dst;

    // send
    ia32_read_msr(IA32_MSR_APIC_BASE, &apic_base);
    apic_base&= LOCAL_APIC_BASE_MSR_MASK;
#ifdef JLMDEBUG
    bprint("about to call do loop base: %p %x\n", apic_base, LOCAL_APIC_ICR_OFFSET);
#endif

    do {
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                           (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);

#ifdef JLMDEBUG
    bprint("back from first do, size of IA32_ICR_LOW %d\n", sizeof(IA32_ICR_LOW));
    bprint("vector_number: 0x%08x\n", vector_number);
    bprint("delivery mode: 0x%08x\n", delivery_mode);
    bprint("destination_shorthand: 0x%08x\n", LOCAL_APIC_BROADCAST_MODE_SPECIFY_CPU);
    bprint("pointer style low: 0x%08x\n", *(uint32_t*)&icr_low);
    bprint("pointer style hi: 0x%08x\n", *(uint32_t*)&icr_high);
#endif
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET_HIGH)= 
                *(uint32_t*)&icr_high;
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET)= *(uint32_t*)&icr_low;
    do {
        startap_stall_using_tsc(10);
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                    (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);
#ifdef JLMDEBUG
    bprint("send_ipi_to_specific_cpu returning\n");
#endif
    return;
}

// Send INIT IPI - SIPI to all active APs
void send_targeted_init_sipi(struct _INIT32_STRUCT *p_init32_data,
                                    VMM_STARTUP_STRUCT *p_startup)
{
    int i;
        
#ifdef JLMDEBUG
    bprint("send_targeted_init_sipi, %d procs at boot.  apic ids: \n",
           p_startup->number_of_processors_at_boot_time);
    for(i=0; i<p_startup->number_of_processors_at_boot_time; i++)
        bprint(" %d", p_startup->cpu_local_apic_ids[i]);
    bprint("\n");
#endif
    for (i = 0; i < p_startup->number_of_processors_at_boot_time - 1; i++) {
        send_ipi_to_specific_cpu(0, LOCAL_APIC_DELIVERY_MODE_INIT, 
                                 p_startup->cpu_local_apic_ids[i+1]);
    }
    startap_stall_using_tsc(10000); // timeout - 10 miliseconds

    // SIPI message contains address of the code, shifted right to 12 bits
    // send it twice - according to manual
    for (i= 0; i<p_startup->number_of_processors_at_boot_time-1; i++) {
        send_ipi_to_specific_cpu(((uint32_t)p_init32_data->i32_low_memory_page)>>12, 
                LOCAL_APIC_DELIVERY_MODE_SIPI, p_startup->cpu_local_apic_ids[i+1]);
    }
    startap_stall_using_tsc(200000); // timeout - 200 miliseconds
    for (i = 0; i < p_startup->number_of_processors_at_boot_time - 1; i++) {
        send_ipi_to_specific_cpu(((uint32_t)p_init32_data->i32_low_memory_page)>>12, 
            LOCAL_APIC_DELIVERY_MODE_SIPI, p_startup->cpu_local_apic_ids[i+1]);
    }
    startap_stall_using_tsc(200000); // timeout - 200 miliseconds
}


// Start all APs in pre-os launch and only active APs in post-os launch and 
// bring them to protected non-paged mode.
// Processors are left in the state were they wait for continuation signal
//    p_init32_data - contains pointer to the free low memory page to be used
//                    for bootstap. After the return this memory is free
//    p_startup - local apic ids of active cpus used post-os launch
//  Return:
//    number of processors that were init (not including BSP)
//    or -1 on errors
uint32_t ap_procs_startup(struct _INIT32_STRUCT *p_init32_data, 
                          VMM_STARTUP_STRUCT *p_startup)
{
#ifdef JLMDEBUG
    bprint("ap_procs_startup init32 data: %p, startup: %p\n", p_init32_data, p_startup);
#endif
    if(NULL==p_init32_data || 0 == p_init32_data->i32_low_memory_page) {
        return (uint32_t)(-1);
    }

    // Stage 1 
    ap_initialize_environment();

    // save IDT and GDT
    __asm__ volatile (
        "\tsgdt %[gp_GDT]\n"
        "\tsidt %[gp_IDT]\n"
    : [gp_GDT] "=m" (gp_GDT), [gp_IDT] "=m" (gp_IDT)
    ::);

    // create AP startup code in low memory
    setup_low_memory_ap_code(p_init32_data->i32_low_memory_page);
#ifdef JLMDEBUG
    bprint("back from setup_low_memory_ap_code\n");
#endif
    // send_targeted_init_sipi(p_init32_data, p_startup);
    // send_init_ipi();
    send_broadcast_init_sipi(p_init32_data);
#ifdef JLMDEBUG
    bprint("back from send_broadcast_init_sipi\n");
#endif

    // wait for predefined timeout
    startap_stall_using_tsc(INITIAL_WAIT_FOR_APS_TIMEOUT_IN_MILIS);
#ifdef JLMDEBUG
    bprint("back from startap_stall_using_tsc\n");
#endif

    // Stage 2 
    g_aps_counter = bsp_enumerate_aps();
#ifdef JLMDEBUG
    bprint("stage 2, num aps: %d\n", g_aps_counter);
#endif
    return g_aps_counter;
}


// Run user specified function on all APs.
// If user function returns it should return in the protected 32bit mode. In this
// case APs enter the wait state once more.
//  continue_ap_boot_func - user given function to continue AP boot
//  any_data - data to be passed to the function
void ap_procs_run(FUNC_CONTINUE_AP_BOOT continue_ap_boot_func, void *any_data)
{
#ifdef JLMDEBUG
    bprint("ap_procs_run function: %p\n", continue_ap_boot_func);
    LOOP_FOREVER
#endif
    g_user_func = continue_ap_boot_func;
    g_any_data_for_user_func = any_data;

    // signal to APs to pass to the next stage
    mp_set_bootstrap_state(MP_BOOTSTRAP_STATE_APS_ENUMERATED);

    // wait until all APs will accept this
    while (g_ready_counter != g_aps_counter) {
        __asm__ volatile (
            "\tpause\n" :::);
    }
    return;
}


// Function  : bsp_enumerate_aps
// Purpose   : Walk through ap_presence_array and count discovered APs.
//           : and modifies array thus it will contain AP IDs,
//           : and not just 1/0.
// Return    : Total number of APs, discovered till now.
// Notes     : Should be called on BSP
uint8_t bsp_enumerate_aps(void)
{
    int       i;
    uint8_t   ap_num = 0;

    for (i = 1; i<NELEMENTS(ap_presence_array); ++i) {
        if (0 != ap_presence_array[i]) {
            ap_presence_array[i] = ++ap_num;
        }
    }
    return ap_num;
}


void ap_initialize_environment(void)
{
    mp_bootstrap_state = MP_BOOTSTRAP_STATE_INIT;
    g_ready_counter = 0;
    g_user_func = 0;
    g_any_data_for_user_func = 0;
}


void mp_set_bootstrap_state(MP_BOOTSTRAP_STATE new_state)
{
#ifdef JLMDEBUG
    bprint("mp_set_bootstrap_state %d\n", new_state);
    LOOP_FOREVER
#endif
    __asm__ volatile (
        "\tpush  %%eax\n"
        "\tmovl  %[new_state], %%eax\n"
        "\tlock; xchgl %%eax, %[mp_bootstrap_state]\n"
        "\tpopl  %%eax\n"
    : [mp_bootstrap_state] "=m" (mp_bootstrap_state), 
      [new_state] "=m" (new_state)
    : : "%eax");
    return;
}

uint32_t startap_rdtsc (uint32_t* upper)
{
    uint32_t ret;
    __asm__ volatile(
        "\tmovl  %[upper], %%ecx\n"
        "\trdtsc\n"
        "\tmovl    (%%ecx), %%edx\n"
        "\tmovl    %%edx,%[ret]\n"
    : [ret] "=m" (ret)
    : [upper] "m"(upper)
    :"%ecx", "%edx");
    return ret;
}


void send_init_ipi(void)
{
    send_ipi_to_all_excluding_self(0, LOCAL_APIC_DELIVERY_MODE_INIT);
}

void send_sipi_ipi(void* code_start)
{
#ifdef JLMDEBUG
    bprint("send_sipi_ipi\n");
#endif
    // SIPI message contains address of the code, shifted right to 12 bits
    send_ipi_to_all_excluding_self( ((uint32_t)code_start)>>12, 
        LOCAL_APIC_DELIVERY_MODE_SIPI);
}


// Send INIT IPI - SIPI to all APs in broadcast mode
void send_broadcast_init_sipi(INIT32_STRUCT *p_init32_data)
{
#ifdef JLMDEBUG
    bprint("send_broadcast_init_sipi\n");
#endif
    send_init_ipi();
#ifdef JLMDEBUG
    bprint("back from send_init_ipi\n");
#endif
    startap_stall_using_tsc(10000); // timeout - 10 miliseconds
#ifdef JLMDEBUG
    bprint("past stall\n");
#endif

    // SIPI message contains address of the code, shifted right to 12 bits
    // send it twice - according to manual
    send_sipi_ipi((void *)p_init32_data->i32_low_memory_page);
    startap_stall_using_tsc(200000); // timeout - 200 miliseconds
#ifdef JLMDEBUG
    bprint("back from first send_sipi_ipi\n");
    return;
    LOOP_FOREVER
#endif
    send_sipi_ipi((void*)p_init32_data->i32_low_memory_page);
    startap_stall_using_tsc(200000); // timeout - 200 milliseconds
#ifdef JLMDEBUG
    bprint("back from second send_sipi_ipi\n");
    LOOP_FOREVER
#endif
}


// send IPI
void send_ipi_to_all_excluding_self(uint32_t vector_number, 
                   uint32_t delivery_mode)
{
    IA32_ICR_LOW           icr_low;
    IA32_ICR_LOW           icr_low_status;
    IA32_ICR_HIGH          icr_high;
    UINT64                 apic_base = 0;

#ifdef JLMDEBUG
    bprint("send_ipi_to_all_excluding_self(%d, %d)\n",
                 vector_number, delivery_mode);
#endif
    vmm_memset(&icr_low, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_low_status, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_high, 0, sizeof(IA32_ICR_HIGH));
    icr_low.bits.vector= vector_number;
    icr_low.bits.delivery_mode = delivery_mode;
    icr_low.bits.vector = vector_number;
    icr_low.bits.delivery_mode = delivery_mode;

    // level is set to 1 (except for INIT_DEASSERT, 
    //   which is not supported in P3 and P4)
    // trigger mode is set to 0 (except for INIT_DEASSERT)
    icr_low.bits.level = 1;
    icr_low.bits.trigger_mode = 0;

    // broadcast mode - ALL_EXCLUDING_SELF
    icr_low.bits.destination_shorthand = 
            LOCAL_APIC_BROADCAST_MODE_ALL_EXCLUDING_SELF;

    // send
    ia32_read_msr(IA32_MSR_APIC_BASE, &apic_base);
    apic_base &= LOCAL_APIC_BASE_MSR_MASK;
    do {
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                    (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);

#ifdef JLMDEBUG
    bprint("back from first do\n");
    bprint("vector_number: 0x%08x\n", vector_number);
    bprint("delivery mode: 0x%08x\n", delivery_mode);
    bprint("pointer style low: 0x%08x\n", *(uint32_t*)&icr_low);
    bprint("pointer style hi: 0x%08x\n", *(uint32_t*)&icr_high);
#endif
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET_HIGH)=
                *(uint32_t*)&icr_high;
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET)= 
                *(uint32_t*)&icr_low;

    do {
        startap_stall_using_tsc(10);
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);
#ifdef JLMDEBUG
    bprint("returning from send_ipi_to_all_excluding_self\n");
#endif
    return;
}

