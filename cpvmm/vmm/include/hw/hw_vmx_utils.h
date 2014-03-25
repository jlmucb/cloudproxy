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

#ifndef _HW_VMX_UTILS_H_
#define _HW_VMX_UTILS_H_
#endif

#include "vmm_defs.h"

//
// wrappers for VMX instructions
//

#ifdef __GNUC__

void vmx_vmptrst( UINT64 *address );
int vmx_vmptrld( UINT64 *address);
int vmx_vmclear( UINT64 *address);

int vmx_vmlaunch( void );
int vmx_vmresume( void );

int vmx_vmwrite( size_t index, size_t *buf);
int vmx_vmread( size_t index, size_t *buf);

int vmx_on( UINT64 *address);
void vmx_off( void );

#else // MS Compiler Intrinsics

extern void          __vmx_vmptrst( unsigned __int64 *VmcsPhysicalAddress );
extern unsigned char __vmx_vmptrld( unsigned __int64 *VmcsPhysicalAddress );
extern unsigned char __vmx_vmclear( unsigned __int64 *VmcsPhysicalAddress );

extern unsigned char __vmx_vmlaunch( void );
extern unsigned char __vmx_vmresume( void );

extern unsigned char __vmx_vmwrite( size_t Field, size_t FieldValue );
extern unsigned char __vmx_vmread( size_t Field, size_t *FieldValue );

extern unsigned char __vmx_on( unsigned __int64 *VmcsPhysicalAddress );
extern void          __vmx_off( void );

#endif



// General note: all functions that return value return the same values
//
// 0 - The operation succeeded.
// 1 - The operation failed with extended status available in the
//     VM-instruction error field of the current VMCS.
// 2 - The operation failed without status available.
//

typedef enum _HW_VMX_RET_VALUE {
    HW_VMX_SUCCESS            = 0,
    HW_VMX_FAILED_WITH_STATUS = 1,
    HW_VMX_FAILED             = 2
} HW_VMX_RET_VALUE;


// VMX ON/OFF
//
// HW_VMX_RET_VALUE hw_vmx_on( UINT64* vmx_on_region_physical_address_ptr )
// void             hw_vmx_off( void )
//
// vmx_on_region_physical_address_ptr is a POINTER TO the VMXON region POINTER.
// The VMXON region POINTER must be 4K page aligned. Size of the
// region is the same as VMCS region size and may be found in IA32_VMX_BASIC MSR

#ifdef __GNUC__
#define hw_vmx_on( _vmx_on_region_physical_address_ptr )                        \
                     (HW_VMX_RET_VALUE)vmx_on(_vmx_on_region_physical_address_ptr)
#define hw_vmx_off() vmx_off()
#else

#define hw_vmx_on( _vmx_on_region_physical_address_ptr )                        \
                     (HW_VMX_RET_VALUE)__vmx_on(_vmx_on_region_physical_address_ptr)
#define hw_vmx_off()                   __vmx_off()
#endif


// Read/write current VMCS pointer
//
// HW_VMX_RET_VALUE hw_vmx_set_current_vmcs( UINT64* vmcs_region_physical_address_ptr )
// void             hw_vmx_get_current_vmcs( UINT64* vmcs_region_physical_address_ptr )
//
// vmcs_region_physical_address_ptr is a POINTER TO the VMCS region POINTER.
// The VMCS region POINTER must be 4K page aligned. Size of the
// region is the same as VMCS region size and may be found in IA32_VMX_BASIC MSR


#ifdef __GNUC__
#define hw_vmx_set_current_vmcs( _vmcs_region_physical_address_ptr )            \
                     (HW_VMX_RET_VALUE)vmx_vmptrld(_vmcs_region_physical_address_ptr)

#define hw_vmx_get_current_vmcs( _vmcs_region_physical_address_ptr )            \
                     vmx_vmptrst(_vmcs_region_physical_address_ptr)
#else

#define hw_vmx_set_current_vmcs( _vmcs_region_physical_address_ptr )            \
                     (HW_VMX_RET_VALUE)__vmx_vmptrld(_vmcs_region_physical_address_ptr)

#define hw_vmx_get_current_vmcs( _vmcs_region_physical_address_ptr )            \
#endif


// Flush current VMCS data + Invalidate current VMCS pointer + Set VMCS launch state
// to the "clear" value (VMLAUNCH required)
//
// HW_VMX_RET_VALUE hw_vmx_flush_current_vmcs( UINT64* vmcs_region_physical_address_ptr )
//
// 1. Save VMCS data to the given region (pointer to pointer)
// 2. If given region is the same as the pointer, that was loaded before using
//    hw_vmx_set_current_vmcs(), the "current VMCS pointer" is set to -1
// 3. Set the VMCS launch state to "clear", so that VMLAUCH will be required
//    to run it and not VMRESUME
//
// vmcs_region_physical_address_ptr is a POINTER TO the VMCS region POINTER.
// The VMCS region POINTER must be 4K page aligned. Size of the
// region is the same as VMCS region size and may be found in IA32_VMX_BASIC MSR


#ifdef __GNUC__

HW_VMX_RET_VALUE hw_vmx_flush_current_vmcs( UINT64 *address); 

#else

#define hw_vmx_flush_current_vmcs(vmcs_region_physical_address_ptr )            \
                     (HW_VMX_RET_VALUE)__vmx_vmclear(vmcs_region_physical_address_ptr)

#endif

//
// Launch/resume guest using "current VMCS pointer".
//
// Launch should be used to first time start this guest on the current physical core
// If guest is relocated to another core, hw_vmx_flush_current_vmcs() should
// be used on the original core and hw_vmx_launch() on the target.
//
// Subsequent guest resumes on the current core should be done using hw_vmx_launch()
//

#ifdef __GNUC__

#define hw_vmx_launch_guest()     (HW_VMX_RET_VALUE)vmx_vmlaunch()
#define hw_vmx_resume_guest()     (HW_VMX_RET_VALUE)vmx_vmresume()

#else

#define hw_vmx_launch_guest()     (HW_VMX_RET_VALUE)__vmx_vmlaunch()
#define hw_vmx_resume_guest()     (HW_VMX_RET_VALUE)__vmx_vmresume()

#endif


// Read/write some field in the "current VMCS"
//
// HW_VMX_RET_VALUE hw_vmx_write_current_vmcs( size_t field_id, size_t value  )
// HW_VMX_RET_VALUE hw_vmx_read_current_vmcs ( size_t field_id, size_t* value )


#ifdef __GNUC__

HW_VMX_RET_VALUE hw_vmx_write_current_vmcs(UINT64 field_id, UINT64 *value );                          

HW_VMX_RET_VALUE hw_vmx_read_current_vmcs(UINT64 field_id, UINT64 *value );
#else

#define hw_vmx_write_current_vmcs( _field_id, _value )                          \
                     (HW_VMX_RET_VALUE)__vmx_vmwrite(_field_id, _value )

#define hw_vmx_read_current_vmcs( _field_id, _value )                           \
                     (HW_VMX_RET_VALUE)__vmx_vmread(_field_id, _value )
#endif 

#endif // _HW_VMX_UTILS_H_
