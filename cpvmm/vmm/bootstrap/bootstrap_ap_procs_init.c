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
#ifdef JLMDEBUG
extern void HexDump(uint8_t*, uint8_t*);
extern uint16_t ia32_read_cs();
extern uint16_t ia32_read_ds();
extern uint16_t ia32_read_ss();
#endif 


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

extern void ia32_read_msr(uint32_t msr_id, uint64_t *p_value);
static uint32_t startap_tsc_ticks_per_msec = 0;


#define  MP_BOOTSTRAP_STATE_INIT  0
#define MP_BOOTSTRAP_STATE_APS_ENUMERATED 1


static volatile uint32_t mp_bootstrap_state;

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


// Layout of low memory page
//   APStartUpCode  <--- low_mem
//   GdtTable       <-- ALIGN16(low_mem+sizeof(APStartupCode))= loc_gdt
//   GDT Register   <-- ALIGN16(loc_gdt+sizeof(gdt))= loc_gdtr

// Uncomment the following line to deadloop in AP startup
// #define BREAK_IN_AP_STARTUP
const uint8_t APStartUpCode[] =
{
#ifdef BREAK_IN_AP_STARTUP
    0xEB, 0xFE,                    // jmp $
#endif
    0x0f, 0x01, 0x16, 0x00, 0x00,  // 00: lgdt  GDTR
    0x0F, 0x20, 0xC0,              // 05: mov  eax,cr0
    0x0C, 0x01,                    // 08: or   al,1
    0x0F, 0x22, 0xC0,              // 10: mov  cr0,eax
    0x66, 0xEA,                    // 13: ljmp CS,CONT16
    0x00, 0x00, 0x00, 0x00,        // 15: CONT16
    0x00, 0x00,                    // 19: CS_VALUE
//CONT16:
    0xFA,                          // 21: cli
    0x66, 0xB8, 0x00, 0x00,        // 22: mov  ax,DS_VALUE
    0x66, 0x8E, 0xD8,              // 26: mov  ds,ax
    0x66, 0xB8, 0x00, 0x00,        // 29: mov  ax,ES_VALUE
    0x66, 0x8E, 0xC0,              // 33: mov  es,ax
    0x66, 0xB8, 0x00, 0x00,        // 36: mov  ax,GS_VALUE
    0x66, 0x8E, 0xE8,              // 40: mov  gs,ax
    0x66, 0xB8, 0x00, 0x00,        // 43: mov  ax,FS_VALUE
    0x66, 0x8E, 0xE0,              // 47: mov  fs,ax
    0x66, 0xB8, 0x00, 0x00,        // 50: mov  ax,SS_VALUE
    0x66, 0x8E, 0xD0,              // 54: mov  ss,ax
    0xB8, 0x00, 0x00, 0x00, 0x00,  // 57: mov  eax,AP_CONTINUE_WAKEUP_CODE
    0xFF, 0xE0,                    // 62: jmp  eax
};

#ifdef BREAK_IN_AP_STARTUP
#define AP_CODE_START                           2
#else
#define AP_CODE_START                           0
#endif

#define GDTR_OFFSET_IN_CODE                      (3 + AP_CODE_START)
#define CONT16_IN_CODE_OFFSET                   (15 + AP_CODE_START)
#define CS_IN_CODE_OFFSET                       (19 + AP_CODE_START)
#define DS_IN_CODE_OFFSET                       (24 + AP_CODE_START)
#define ES_IN_CODE_OFFSET                       (31 + AP_CODE_START)
#define GS_IN_CODE_OFFSET                       (38 + AP_CODE_START)
#define FS_IN_CODE_OFFSET                       (45 + AP_CODE_START)
#define SS_IN_CODE_OFFSET                       (52 + AP_CODE_START)
#define AP_CONTINUE_WAKEUP_CODE_IN_CODE_OFFSET  (58 + AP_CODE_START)

#define CONT16_VALUE_OFFSET                     (21 + AP_CODE_START)


void     ap_continue_wakeup_code(void);
void     ap_continue_wakeup_code_C(uint32_t local_apic_id);
uint8_t  bsp_enumerate_aps(void);
void     ap_initialize_environment(void);
void     mp_set_bootstrap_state(uint32_t new_state);


uint64_t startap_rdtsc()
{
    uint64_t  ret= 0;
    uint64_t  hi= 0;
    uint64_t  lo= 0;

    __asm__ volatile(
        "\trdtsc\n"
        "\tmovl  %%eax,%[lo]\n"
        "\tmovl  %%edx,%[hi]\n"
    : [hi] "=m" (hi), [lo] "=m" (lo)
    : :);
    ret= (hi<<32ULL)|lo;
    return ret;
}


// location of gdt and gdtr in low memory page
uint32_t    loc_gdt= 0;
uint32_t    loc_gdtr= 0;
uint32_t    loc_idtr= 0;


// Setup AP low memory startup code
void setup_low_memory_ap_code(uint32_t temp_low_memory_4K)
{
    uint8_t*    code_to_patch = (uint8_t*)temp_low_memory_4K;
    uint32_t    end_page;
    UINT16      cs_sel= 0;
    UINT16      ds_sel= 0;
    UINT16      es_sel= 0;
    UINT16      gs_sel= 0;
    UINT16      fs_sel= 0;
    UINT16      ss_sel= 0;

#ifdef JLMDEBUG1
    bprint("setup_low_memory\n");
#endif

    // zero low memory
    vmm_memset(code_to_patch, 0, 0x1000);

    // Copy the Startup code to the beginning of the page
    vmm_memcpy(code_to_patch, (const void*)APStartUpCode, sizeof(APStartUpCode));

    IA32_GDTR current_gdtr;
    //IA32_IDTR current_idtr;
    __asm__ volatile (
       "\tsgdt  %[current_gdtr]\n"
       // "\tsidt  %[current_idtr]\n"
    :[current_gdtr] "=m" (current_gdtr)// ,
     // [current_idtr] "=m" (current_idtr)
    ::);

    loc_gdt= (temp_low_memory_4K+sizeof(APStartUpCode)+15)&(uint32_t)0xfffffff0;
    loc_gdtr= (loc_gdt+current_gdtr.limit+16)&(uint32_t)0xfffffff0;
    loc_idtr= (loc_gdtr+6);

    // GDTR in page
    *(uint16_t*)loc_gdtr= current_gdtr.limit;
    *(uint32_t*)(loc_gdtr+2)= loc_gdt;
    // IDTR in page
    // *(uint16_t*)loc_idtr= current_idtr.limit;
    // *(uint32_t*)(loc_idtr+2)= current_idtr.base;
  
    cs_sel= ia32_read_cs();
    ds_sel= ia32_read_ds();
    ss_sel= ia32_read_ss();
    es_sel= ia32_read_ds();
    fs_sel= ia32_read_ds();

    // Patch the startup code
    *((UINT16*)(code_to_patch+GDTR_OFFSET_IN_CODE))= (uint16_t) loc_gdtr;
    *((uint32_t*)(code_to_patch+CONT16_IN_CODE_OFFSET)) =
                                   (uint32_t)code_to_patch + CONT16_VALUE_OFFSET;
    *((UINT16*)(code_to_patch+CS_IN_CODE_OFFSET))= cs_sel;
    *((UINT16*)(code_to_patch+DS_IN_CODE_OFFSET))= ds_sel;
    *((UINT16*)(code_to_patch+ES_IN_CODE_OFFSET))= es_sel;
    *((UINT16*)(code_to_patch+GS_IN_CODE_OFFSET))= gs_sel;
    *((UINT16*)(code_to_patch+FS_IN_CODE_OFFSET))= fs_sel;
    *((UINT16*)(code_to_patch+SS_IN_CODE_OFFSET))= ss_sel;
    *((uint32_t*)(code_to_patch+AP_CONTINUE_WAKEUP_CODE_IN_CODE_OFFSET)) =
                                            (uint32_t)(ap_continue_wakeup_code);

    // GDT in page
    vmm_memcpy((uint8_t*)loc_gdt, (uint8_t*)current_gdtr.base, current_gdtr.limit+1);

#if 0
    // this loops after the ljmp location
    // uint8_t* pnop= code_to_patch+CONT16_IN_CODE_OFFSET+6;
    // uint8_t* pnop= code_to_patch+57;
    uint8_t* pnop= code_to_patch+62;
    *(pnop++)= 0xeb; *(pnop++)= 0xfe; 
    // *(pnop++)= 0x90; *(pnop++)= 0x90; 
    //*(pnop++)= 0x90; *(pnop++)= 0x90; 
    //*(pnop++)= 0x90; *(pnop++)= 0x90; 
#endif

#ifdef JLMDEBUG
    end_page= loc_idtr+6;
    bprint("code_to_patch: 0x%08x, ljmp offset offset: 0x%08x, address: 0x%08x\n",  
           code_to_patch, CONT16_VALUE_OFFSET, code_to_patch+CONT16_VALUE_OFFSET);
    bprint("cs_sel: 0x%04x, ", cs_sel);
    bprint("ds_sel: 0x%04x, ", ds_sel);
    bprint("ss_sel: 0x%04x\n", ss_sel);
    bprint("loc_gdt: 0x%08x, loc_gdtr: 0x%08x, base: 0x%08x, limit: 0x%04x\n",
            loc_gdt, loc_gdtr, loc_gdt, current_gdtr.limit);
    HexDump(code_to_patch, (uint8_t*)end_page);
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


__asm__(
".text\n"
".globl ap_continue_wakeup_code\n"
".type ap_continue_wakeup_code,@function\n"
"ap_continue_wakeup_code:\n"
        "\tcli\n"
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
        // last debug place
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
        "\tjmp .\n"    // debug
        "\txor   %ecx,  %ecx\n"
        // now ecx contains AP ordered ID [1..Max]
        "\tmovb  (%edx), %cl\n"
        "\tmov   %ecx, %eax\n"
        //  AP starts from 1, so subtract one to get proper index in g_stacks_arr
        // "\tdec   %eax\n"

        // point edx to right stack
        "\tmov   evmm_stack_pointers_array, %edx\n"
        "\tlea   (%edx, %eax, 4), %edx\n"
        "\tmov   (%edx), %esp\n"

        // setup GDT
        "\tlgdt  gp_GDT\n"

        // setup IDT
        "\tlidt gp_IDT\n"

        // enter "C" function
        //  push  AP ordered ID
        "\tmov    %ecx, %edi\n"
        // should never return
        "\tcall  ap_continue_wakeup_code_C\n"
);


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
    uint32_t   c= 0;
    for(c= 0; c<stall_usec; c++)
        read_port_8(IA32_DEBUG_IO_PORT);
    return;
}


// Calibrate the internal variable with number of TSC ticks pers second.
// Should only be called at initialization, as it relies on startap_stall()
void startap_calibrate_tsc_ticks_per_msec(void)
{
    uint64_t start_tsc, end_tsc;

    start_tsc= startap_rdtsc();
    startap_stall(1000);   // 1 ms
    end_tsc= startap_rdtsc();
    startap_tsc_ticks_per_msec= (uint32_t)(end_tsc-start_tsc);
#ifdef JLMDEBUG
    bprint("ticks/ms: %d\n", startap_tsc_ticks_per_msec);
#endif
    return;
}


// Stall (busy loop) for a given time, using the CPU TSC register.
// Note that, depending on the CPU and ASCI modes, the stall accuracy 
// may be rough.
void startap_stall_using_tsc(uint32_t stall_usec)
{
    uint64_t   start_tsc, end_tsc;

    // Initialize startap_tsc_ticks_per_msec. Happens at boot time
    if(startap_tsc_ticks_per_msec == 0) {
        startap_calibrate_tsc_ticks_per_msec();
    }
    // Calculate the start_tsc and end_tsc
    start_tsc = startap_rdtsc();
    end_tsc= startap_rdtsc()+(((uint64_t)stall_usec/1000)*
                             (uint64_t)startap_tsc_ticks_per_msec);
    while (start_tsc<end_tsc) {
        __asm__ volatile (
            "\tpause\n"
        :::);
        start_tsc = startap_rdtsc();
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
#ifdef JLMDEBUG1
    bprint("about to call do loop base: %p %x\n", apic_base, LOCAL_APIC_ICR_OFFSET);
#endif

    do {
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                           (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);

#ifdef JLMDEBUG
    bprint("vector: 0x%04x, ", vector_number);
    bprint("delivery: 0x%04x\n", delivery_mode);
    bprint("shorthand: 0x%04x, ", LOCAL_APIC_BROADCAST_MODE_SPECIFY_CPU);
    bprint("pointer hi: 0x%08x, ", *(uint32_t*)&icr_high);
    bprint("low: 0x%08x\n", *(uint32_t*)&icr_low);
#endif
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET_HIGH)= 
                *(uint32_t*)&icr_high;
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET)= *(uint32_t*)&icr_low;
    do {
        startap_stall_using_tsc(10000);
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
    startap_stall_using_tsc(10000); // timeout - 10 milliseconds

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
    send_broadcast_init_sipi(p_init32_data);

    // wait for predefined timeout
    startap_stall_using_tsc(INITIAL_WAIT_FOR_APS_TIMEOUT_IN_MILIS);

    // Stage 2 
    g_aps_counter = bsp_enumerate_aps();
#ifdef JLMDEBUG1
    bprint("patched code\n");
    HexDump((uint8_t*) p_init32_data->i32_low_memory_page, 
        (uint8_t*) p_init32_data->i32_low_memory_page+sizeof(APStartUpCode));
    bprint("gdt\n");
    HexDump((uint8_t*) p_init32_data->i32_low_memory_page+GDT_OFFSET_IN_PAGE, 
        (uint8_t*) p_init32_data->i32_low_memory_page+GDT_OFFSET_IN_PAGE+96);
#endif
#ifdef JLMDEBUG
    bprint("gdt limit: %d, gdt base: 0x%08x\n", *(uint16_t*)(&gp_GDT[0]),
            *(uint32_t*)(&gp_GDT[2]));
    bprint("idt limit: %d, idt base: 0x%08x\n", *(uint16_t*)(&gp_IDT[0]),
            *(uint32_t*)(&gp_IDT[2]));
    bprint("mp_bootstrap_state: %d\n", mp_bootstrap_state);
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


void mp_set_bootstrap_state(uint32_t new_state)
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
    : [mp_bootstrap_state] "=m" (mp_bootstrap_state)
    : [new_state] "g" (new_state)
    : "%eax");
    return;
}


void send_init_ipi(void)
{
    send_ipi_to_all_excluding_self(0, LOCAL_APIC_DELIVERY_MODE_INIT);
}

void send_sipi_ipi(void* code_start)
{
    // SIPI message contains address of the code, shifted right to 12 bits
    send_ipi_to_all_excluding_self(((uint32_t)code_start)>>12, 
        LOCAL_APIC_DELIVERY_MODE_SIPI);
}


// Send INIT IPI - SIPI to all APs in broadcast mode
void send_broadcast_init_sipi(INIT32_STRUCT *p_init32_data)
{
    send_init_ipi();
    startap_stall_using_tsc(10000); // timeout - 10 milliseconds

    // SIPI message contains address of the code, shifted right to 12 bits
    // send it twice - according to manual
    send_sipi_ipi((void *)p_init32_data->i32_low_memory_page);
    startap_stall_using_tsc(200000); // timeout - 200 milliseconds
#ifdef JLMDEBUG
    bprint("back from first send_sipi_ipi\n");
#endif
    send_sipi_ipi((void*)p_init32_data->i32_low_memory_page);
    startap_stall_using_tsc(200000); // timeout - 200 milliseconds
#ifdef JLMDEBUG
    bprint("back from second send_sipi_ipi\n");
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

#ifdef JLMDEBUG1
    bprint("send_ipi_to_all_excluding_self(%d, %d)\n",
                 vector_number, delivery_mode);
#endif
    vmm_memset(&icr_low, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_low_status, 0, sizeof(IA32_ICR_LOW));
    vmm_memset(&icr_high, 0, sizeof(IA32_ICR_HIGH));
    icr_low.bits.vector= vector_number;
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
    bprint("vector: 0x%04x, ", vector_number);
    bprint("mode: 0x%04x, ", delivery_mode);
    bprint("pointer hi: 0x%08x, ", *(uint32_t*)&icr_high);
    bprint("low: 0x%08x\n", *(uint32_t*)&icr_low);
#endif
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET_HIGH)=
                *(uint32_t*)&icr_high;
    *(uint32_t*)(uint32_t)(apic_base+LOCAL_APIC_ICR_OFFSET)= 
                *(uint32_t*)&icr_low;

    do {
        startap_stall_using_tsc(10000);
        *(uint32_t*)&icr_low_status= *(uint32_t*)(uint32_t)
                (apic_base+LOCAL_APIC_ICR_OFFSET);
    } while (icr_low_status.bits.delivery_status!=0);
#ifdef JLMDEBUG1
    bprint("returning from send_ipi_to_all_excluding_self\n");
#endif
    return;
}

