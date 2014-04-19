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

#ifndef _HW_UTILS_H_
#define _HW_UTILS_H_

#include "vmm_defs.h"
#include "gdt.h"

BOOLEAN hw_rdmsr_safe(UINT32 msr_id, UINT64 *value, VECTOR_ID *fault_vector, UINT32 *error_code);
BOOLEAN hw_wrmsr_safe(UINT32 msr_id, UINT64 value, VECTOR_ID *fault_vector, UINT32 *error_code);

#ifdef __GNUC__

UINT8 hw_read_port_8( UINT16 port );
UINT16 hw_read_port_16( UINT16 port );
UINT32 hw_read_port_32( UINT16 port );
void hw_write_port_8( UINT16 port, UINT8 val8 );
void hw_write_port_16( UINT16 port, UINT16 val16 );
void hw_write_port_32( UINT16 port, UINT32 val32 );

void hw_lidt(void *Source);
void hw_sidt(void *Destination);
void hw_write_msr( UINT32 msr_id, UINT64 Value );
UINT64 hw_read_msr( UINT32 msr_id );

// find first bit set
//  forward: LSB->MSB
//  backward: MSB->LSB
// Return 0 if no bits set
// Fills "bit_number" with the set bit position zero based
// BOOLEAN hw_scan_bit_forward( UINT32& bit_number, UINT32 bitset );
// BOOLEAN hw_scan_bit_backward( UINT32& bit_number, UINT32 bitset );
// BOOLEAN hw_scan_bit_forward64( UINT32& bit_number, UINT64 bitset );
// BOOLEAN hw_scan_bit_backward64( UINT32& bit_number, UINT64 bitset );

BOOLEAN hw_scan_bit_forward( UINT32 *bit_number_ptr, UINT32 bitset );
BOOLEAN hw_scan_bit_backward( UINT32 *bit_number_ptr, UINT32 bitset );
BOOLEAN hw_scan_bit_forward64( UINT32 *bit_number_ptr, UINT64 bitset );
BOOLEAN hw_scan_bit_backward64( UINT32 *bit_number_ptr, UINT64 bitset );

UINT64 hw_rdtsc(void);
UINT64 hw_read_cr0(void);
UINT64 hw_read_cr2(void);
UINT64 hw_read_cr3(void);
UINT64 hw_read_cr4(void);
UINT64 hw_read_cr8(void);
void   hw_write_cr0(UINT64 Data);
void   hw_write_cr3(UINT64 Data);
void   hw_write_cr4(UINT64 Data);
void   hw_write_cr8(UINT64 Data);

UINT64 hw_read_dr0(void);
UINT64 hw_read_dr1(void);
UINT64 hw_read_dr2(void);
UINT64 hw_read_dr3(void);
UINT64 hw_read_dr4(void);
UINT64 hw_read_dr5(void);
UINT64 hw_read_dr6(void);
UINT64 hw_read_dr7(void);

void hw_write_dr0(UINT64 value);
void hw_write_dr1(UINT64 value);
void hw_write_dr2(UINT64 value);
void hw_write_dr3(UINT64 value);
void hw_write_dr4(UINT64 value);
void hw_write_dr5(UINT64 value);
void hw_write_dr6(UINT64 value);
void hw_write_dr7(UINT64 value);
#define hw_read_dr(__dbg_reg) hw_read_dr##__dbg_reg()
#define hw_write_dr(__dbg_reg, __value) hw_write_dr##__dbg_reg(__value)

void hw_invlpg(void *address);
void hw_wbinvd(void);
void hw_halt( void );

#else

extern unsigned char __inbyte( unsigned short Port );
extern unsigned short _inpw( unsigned short port );
extern unsigned long _inpd( unsigned short port );
extern void __outbyte( unsigned short Port, unsigned char Data );
extern unsigned short _outpw( unsigned short port, unsigned short dataword );
extern unsigned long _outpd( unsigned short port, unsigned long dataword );
extern void __lidt(void *Source);
extern void __sidt(void *Destination);
extern void __writemsr( unsigned long Register, unsigned __int64 Value );
extern unsigned __int64 __readmsr( int msr_id );
extern unsigned char _BitScanForward( unsigned long * Index, unsigned long Mask );
extern unsigned char _BitScanReverse( unsigned long * Index, unsigned long Mask );
extern unsigned char _BitScanForward64( unsigned long * Index, unsigned __int64 Mask );
extern unsigned char _BitScanReverse64( unsigned long * Index, unsigned __int64 Mask );
extern unsigned __int64 __rdtsc(void);
extern unsigned __int64 __readcr0(void);
extern unsigned __int64 __readcr2(void);
extern unsigned __int64 __readcr3(void);
extern unsigned __int64 __readcr4(void);
extern unsigned __int64 __readcr8(void);
extern void __writecr0(unsigned __int64 Data);
extern void __writecr3(unsigned __int64 Data);
extern void __writecr4(unsigned __int64 Data);
extern void __writecr8(unsigned __int64 Data);
extern unsigned __int64 __readdr(unsigned int DebugRegister);
extern void __writedr(unsigned DebugRegister, unsigned __int64 DebugValue);
extern void __invlpg(void* Address);
extern void __wbinvd(void);
extern void __halt( void );

#define hw_read_port_8( port )  (UINT8)__inbyte( (unsigned short)(port))
#define hw_read_port_16( port )  (UINT16)_inpw( (unsigned short)(port))
#define hw_read_port_32( port )  (UINT32)_inpd( (unsigned short)(port))
#define hw_write_port_8( port, data )  __outbyte( (unsigned short)(port),       \
                                                  (unsigned char)(data))
#define hw_write_port_16( port, data )  _outpw( (unsigned short)(port),       \
                                                (unsigned short)(data))
#define hw_write_port_32( port, data )  _outpd( (unsigned short)(port),\
                                                (unsigned long)(data))

#define hw_lidt( _idtr ) __lidt( _idtr )
#define hw_sidt( _idtr ) __sidt( _idtr )

#define hw_read_msr( _register )           __readmsr( _register )
#define hw_write_msr( _register, _value )   __writemsr( _register, _value )

#define hw_scan_bit_forward( _bit_number_ptr, _bitset )                         \
                           (UINT8)_BitScanForward( (unsigned long *) _bit_number_ptr, _bitset )
#define hw_scan_bit_backward( _bit_number_ptr, _bitset )                        \
                           (UINT8)_BitScanReverse( (unsigned long *) _bit_number_ptr, _bitset )

#define hw_scan_bit_forward64( _bit_number_ptr, _bitset )                       \
                           (UINT8)_BitScanForward64( (unsigned long *) _bit_number_ptr, _bitset )
#define hw_scan_bit_backward64( _bit_number_ptr, _bitset )                      \
                           (UINT8)_BitScanReverse64( (unsigned long *) _bit_number_ptr, _bitset )

#define hw_rdtsc() __rdtsc()
#define hw_read_cr0()           __readcr0()
#define hw_write_cr0( _value )  __writecr0( _value )
#define hw_read_cr2()           __readcr2()
#define hw_read_cr3()           __readcr3()
#define hw_write_cr3( _value )  __writecr3( _value )
#define hw_read_cr4()           __readcr4()
#define hw_write_cr4( _value )  __writecr4( _value )
#define hw_read_cr8()           __readcr8()
#define hw_write_cr8( _value )  __writecr8( _value )
#define hw_read_dr( _index )            __readdr( _index )
#define hw_write_dr( _index, _value )   __writedr( _index, _value )
#define hw_invlpg(addr) __invlpg((void*)addr)
#define hw_wbinvd() __wbinvd()
#define hw_halt() __halt()

#endif // ! __GNUC__


typedef struct {
    UINT64   m_rax;
    UINT64   m_rbx;
    UINT64   m_rcx;
    UINT64   m_rdx;
} PACKED CPUID_PARAMS;

void hw_cpuid(CPUID_PARAMS *);

typedef struct _CPUID_INFO_STRUCT {
    int data[4];
} CPUID_INFO_STRUCT;


// CPUID leaf and ext leaf definitions
#define CPUID_LEAF_1H       0x1
#define CPUID_LEAF_3H       0x3
#define CPUID_LEAF_7H       0x7

#define CPUID_SUB_LEAF_0H   0x0  //sub leaf input ECX = 0

#define CPUID_EXT_LEAF_1H   0x80000001
#define CPUID_EXT_LEAF_2H   0x80000002


// CPUID bit support for h/w features
#define CPUID_LEAF_1H_ECX_VMX_SUPPORT        5  // ecx bit 5 for VMX 
#define CPUID_LEAF_1H_ECX_SMX_SUPPORT        6  // ecx bit 6 for SMX
#define CPUID_LEAF_1H_ECX_PCID_SUPPORT       17 // ecx bit 17 for PCID (CR4.PCIDE)

#define CPUID_EXT_LEAF_1H_EDX_SYSCALL_SYSRET 11 // edx bit 11 for syscall/ret
#define CPUID_EXT_LEAF_1H_EDX_RDTSCP_BIT     27 // edx bit 27 for rdtscp

// ebx bit 10 for INVPCID (INPUT leaf EAX=07H, ECX=0H)
#define CPUID_LEAF_7H_0H_EBX_INVPCID_BIT     10 

// ebx bit 0 for supporting RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
#define CPUID_LEAF_7H_0H_EBX_FSGSBASE_BIT     0

#define CPUID_VALUE_EAX( cpuid_info ) ((UINT32)((cpuid_info).data[0]))
#define CPUID_VALUE_EBX( cpuid_info ) ((UINT32)((cpuid_info).data[1]))
#define CPUID_VALUE_ECX( cpuid_info ) ((UINT32)((cpuid_info).data[2]))
#define CPUID_VALUE_EDX( cpuid_info ) ((UINT32)((cpuid_info).data[3]))

#define cpuid( p_cpuid_info, type )                                            \
{                                                                              \
    CPUID_PARAMS __cpuid_params;                                               \
    __cpuid_params.m_rax = type;                                               \
    hw_cpuid(&__cpuid_params);                                                 \
                                                                               \
    (p_cpuid_info)->data[0] = (UINT32)__cpuid_params.m_rax;                      \
    (p_cpuid_info)->data[1] = (UINT32)__cpuid_params.m_rbx;                      \
    (p_cpuid_info)->data[2] = (UINT32)__cpuid_params.m_rcx;                      \
    (p_cpuid_info)->data[3] = (UINT32)__cpuid_params.m_rdx;                      \
}

INLINE UINT32 hw_read_address_size(void)
{
    CPUID_INFO_STRUCT cpu_info;
    cpuid ( &cpu_info, 0x80000008);
    return CPUID_VALUE_EAX(cpu_info);
}

INLINE BOOLEAN is_rdtscp_supported(void)
{
    CPUID_PARAMS cpuid_params = {0};
    cpuid_params.m_rax = CPUID_EXT_LEAF_1H; 
    hw_cpuid(&cpuid_params);  
    return BIT_GET64( cpuid_params.m_rdx, CPUID_EXT_LEAF_1H_EDX_RDTSCP_BIT)? TRUE:FALSE;
}


INLINE BOOLEAN is_invpcid_supported(void)
{
    CPUID_PARAMS cpuid_params = {0};

    cpuid_params.m_rax = CPUID_LEAF_7H; 
    cpuid_params.m_rcx = CPUID_SUB_LEAF_0H; 
    hw_cpuid(&cpuid_params);  
    return BIT_GET64( cpuid_params.m_rbx, CPUID_LEAF_7H_0H_EBX_INVPCID_BIT)? TRUE:FALSE;
}

INLINE BOOLEAN is_fsgsbase_supported(void)
{
    CPUID_PARAMS cpuid_params = {0};

    cpuid_params.m_rax = CPUID_LEAF_7H; 
    cpuid_params.m_rcx = CPUID_SUB_LEAF_0H; 
    hw_cpuid(&cpuid_params);  
    return BIT_GET64( cpuid_params.m_rbx, CPUID_LEAF_7H_0H_EBX_FSGSBASE_BIT)? TRUE:FALSE;
}


INLINE BOOLEAN is_pcid_supported(void)
{
    CPUID_PARAMS cpuid_params = {0};

    cpuid_params.m_rax = CPUID_LEAF_1H; 
    hw_cpuid(&cpuid_params);  
    return BIT_GET64( cpuid_params.m_rcx, CPUID_LEAF_1H_ECX_PCID_SUPPORT)? TRUE:FALSE;
}

void    hw_perform_asm_iret(void);
void    hw_lgdt(void * gdtr);
void    hw_sgdt(void * gdtr);
UINT16  hw_read_cs(void);
void    hw_write_cs(UINT16);
UINT16  hw_read_ds(void);
void    hw_write_ds(UINT16);
UINT16  hw_read_es(void);
void    hw_write_es(UINT16);
UINT16  hw_read_ss(void);
void    hw_write_ss(UINT16);
UINT16  hw_read_fs(void);
void    hw_write_fs(UINT16);
UINT16   hw_read_gs(void);
void     hw_write_gs(UINT16);
UINT16   hw_read_tr(void);
void     hw_write_tr(UINT16);
UINT16   hw_read_ldtr(void);
void     hw_write_ldtr(UINT16);
void hw_set_stack_pointer(HVA new_stack_pointer,
                          main_continue_fn func, void* params);
UINT64 hw_read_rsp(void);
void hw_cpuid(CPUID_PARAMS *);
void hw_write_cr2( UINT64 value );


#define hw_flash_tlb()      hw_write_cr3(hw_read_cr3())

void hw_reset_platform(void);
void hw_stall(UINT32 stall_usec);
void hw_calibrate_tsc_ticks_per_second(void);
UINT64 hw_get_tsc_ticks_per_second(void);
void hw_stall_using_tsc(UINT32 stall_usec);


// Test for ready-to-be-accepted fixed interrupts.
BOOLEAN hw_is_ready_interrupt_exist(void);

void hw_write_to_smi_port(
    UINT64 * p_rax,     // rcx
    UINT64 * p_rbx,     // rdx
    UINT64 * p_rcx,     // r8
    UINT64 * p_rdx,     // r9
    UINT64 * p_rsi,     // on the stack
    UINT64 * p_rdi,     // on the stack
    UINT64 * p_rflags); // on the stack
void hw_enable_interrupts(void);
void hw_disable_interrupts(void);
void hw_fxsave( void* buffer );
void hw_fxrestore( void* buffer );

INLINE UINT32 hw_read_memory_mapped_register(ADDRESS base, ADDRESS offset)
{
    return *((volatile UINT32 *) (base + offset));
}

INLINE UINT32 hw_write_memory_mapped_register(ADDRESS base, ADDRESS offset, UINT32 value)
{
    return *((volatile UINT32 *) (base + offset)) = value;
}

INLINE UINT64 hw_read_memory_mapped_register64(ADDRESS base, ADDRESS offset)
{
    return *((volatile UINT64 *) (base + offset));
}

INLINE UINT64 hw_write_memory_mapped_register64(ADDRESS base, ADDRESS offset, UINT64 value)
{
    return *((volatile UINT64 *) (base + offset)) = value;
}

#endif // _HW_UTILS_H_

