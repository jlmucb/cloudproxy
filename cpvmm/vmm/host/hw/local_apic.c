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

#include "local_apic.h"
#include "em64t_defs.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "host_memory_manager_api.h"
#include "memory_allocator.h"
#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(LOCAL_APIC_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(LOCAL_APIC_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#pragma warning( disable : 4100)        // unreferenced formal parameter
#define STRINGIFY(x)     #x


//                       Local Macros and Types

typedef struct _LOCAL_APIC_PER_CPU_DATA {
    ADDRESS                 lapic_base_address_hpa;
    ADDRESS                 lapic_base_address_hva;

    LOCAL_APIC_MODE         lapic_mode;
    CPU_ID                  lapic_cpu_id;
    UINT8                   pad[2];

    void (*lapic_read_reg) (const struct _LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id, void* p_data, unsigned bytes);
    void (*lapic_write_reg)(const struct _LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id, void* p_data, unsigned bytes);

} LOCAL_APIC_PER_CPU_DATA;

// array per hw cpu
static LOCAL_APIC_PER_CPU_DATA* lapic_cpu_data = NULL;

#define IA32_APIC_BASE_MSR_BSP              0x100
#define IA32_APIC_BASE_MSR_X2APIC_ENABLE    0x400
#define IA32_APIC_BASE_MSR_GLOBAL_ENABLE    0x800
#define IA32_APIC_BASE_MSR_PHY_ADDRESS      0xFFFFFF000

// SW enable/disable flag - bit 8 in the Spurious Vector Register
#define IA32_APIC_SW_ENABLE_BIT_IDX         8

#define ACCESS_RO   READ_ACCESS
#define ACCESS_WO   WRITE_ACCESS
#define ACCESS_RW   READ_WRITE_ACCESS

#define MODE_NO   0
#define MODE_MMIO 1
#define MODE_MSR  2
#define MODE_BOTH (MODE_MMIO | MODE_MSR)


typedef struct _LOCAL_APIC_REGISTER {
    UINT32  offset;
    UINT8   access;
    UINT8   modes;
    UINT16  x2_size;
    char    *name;
} LOCAL_APIC_REGISTER;

#define LOCAL_APIC_REG_MSR(__reg_id)        (LOCAL_APIC_REG_MSR_BASE + (__reg_id))
#define LOCAL_APIC_REG_ADDRESS(lapic_data, __reg_id) ((lapic_data)->lapic_base_address_hva + ((__reg_id) << 4))

#define GET_OTHER_LAPIC(__cpu_id)  (lapic_cpu_data + (__cpu_id))
#define GET_CPU_LAPIC()         GET_OTHER_LAPIC(hw_cpu_id())

/*
 *               Forward Declarations for Local Functions
 */
#ifdef INCLUDE_UNUSED_CODE
static void lapic_mode_disable(void);
static void lapic_mode_enable_from_disabled(void);
static void lapic_mode_enable_from_x2(void);
static void lapic_mode_x2_from_disabled(void);
static void lapic_mode_x2_from_enabled(void);
#endif
static void lapic_read_reg_msr(const LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned bytes);
static void lapic_write_reg_msr(const LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned bytes);
static LOCAL_APIC_MODE  local_apic_discover_mode(void);
static void lapic_read_reg_mmio(const LOCAL_APIC_PER_CPU_DATA* data , LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned not_used);
static void lapic_write_reg_mmio(const LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned not_used);
static void lapic_fill_current_mode( LOCAL_APIC_PER_CPU_DATA* data );
#ifdef INCLUDE_UNUSED_CODE
// find highest set bit in 256bit reg (8 sequential regs 32bit each). Return UINT32_ALL_ONES if no 1s found.
static UINT32 find_highest_bit_in_256bit_reg( LOCAL_APIC_PER_CPU_DATA* data, LOCAL_APIC_REG_ID reg_id );
#endif
static BOOLEAN
local_apic_ipi_verify_params(LOCAL_APIC_IPI_DESTINATION_SHORTHAND dst_shorthand,
                             LOCAL_APIC_IPI_DELIVERY_MODE delivery_mode,
                             UINT8  vector,
                             LOCAL_APIC_IPI_LEVEL level,
                             LOCAL_APIC_IPI_TRIGGER_MODE trigger_mode);


#ifdef INCLUDE_UNUSED_CODE


static const LOCAL_APIC_REGISTER lapic_registers[] =
{
    { 0x00, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x01, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x02, ACCESS_RO, MODE_BOTH, 4, "ID" },
    { 0x03, ACCESS_RO, MODE_BOTH, 4, "Version" },
    { 0x04, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x05, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x06, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x07, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x08, ACCESS_RW, MODE_BOTH, 4, "TPR" },
    { 0x09, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x0A, ACCESS_RO, MODE_BOTH, 4, "PPR" },
    { 0x0B, ACCESS_WO, MODE_BOTH, 4, "EOI" },           // GP fault on non-zero write
    { 0x0C, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x0D, ACCESS_RO, MODE_BOTH, 4, "Logical Destination" },
    { 0x0E, ACCESS_RW, MODE_MMIO, 4, "Destination Format" },
    { 0x0F, ACCESS_RW, MODE_BOTH, 4, "Spurious interrupt Vector" },
    { 0x10, ACCESS_RO, MODE_BOTH, 4, "ISR[31..00]" },
    { 0x11, ACCESS_RO, MODE_BOTH, 4, "ISR[63..32]" },
    { 0x12, ACCESS_RO, MODE_BOTH, 4, "ISR[95..64]" },
    { 0x13, ACCESS_RO, MODE_BOTH, 4, "ISR[127..96]" },
    { 0x14, ACCESS_RO, MODE_BOTH, 4, "ISR[159..128]" },
    { 0x14, ACCESS_RO, MODE_BOTH, 4, "ISR[191..160]" },
    { 0x16, ACCESS_RO, MODE_BOTH, 4, "ISR[223..192]" },
    { 0x17, ACCESS_RO, MODE_BOTH, 4, "ISR[255..224]" },
    { 0x18, ACCESS_RO, MODE_BOTH, 4, "TMR[31..00]" },
    { 0x19, ACCESS_RO, MODE_BOTH, 4, "TMR[63..32]" },
    { 0x1A, ACCESS_RO, MODE_BOTH, 4, "TMR[95..64]" },
    { 0x1B, ACCESS_RO, MODE_BOTH, 4, "TMR[127..96]" },
    { 0x1C, ACCESS_RO, MODE_BOTH, 4, "TMR[159..128]" },
    { 0x1D, ACCESS_RO, MODE_BOTH, 4, "TMR[191..160]" },
    { 0x1E, ACCESS_RO, MODE_BOTH, 4, "TMR[223..192]" },
    { 0x1F, ACCESS_RO, MODE_BOTH, 4, "TMR[255..224]" },
    { 0x20, ACCESS_RO, MODE_BOTH, 4, "IRR[31..00]" },
    { 0x21, ACCESS_RO, MODE_BOTH, 4, "IRR[63..32]" },
    { 0x22, ACCESS_RO, MODE_BOTH, 4, "IRR[95..64]" },
    { 0x23, ACCESS_RO, MODE_BOTH, 4, "IRR[127..96]" },
    { 0x24, ACCESS_RO, MODE_BOTH, 4, "IRR[159..128]" },
    { 0x24, ACCESS_RO, MODE_BOTH, 4, "IRR[191..160]" },
    { 0x26, ACCESS_RO, MODE_BOTH, 4, "IRR[223..192]" },
    { 0x27, ACCESS_RO, MODE_BOTH, 4, "IRR[255..224]" },
    { 0x28, ACCESS_RW, MODE_BOTH, 4, "Error Status" },  // GP fault on non-zero write
    { 0x29, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2A, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2B, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2C, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2D, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2E, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x2F, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x30, ACCESS_RW, MODE_BOTH, 8, "Interrupt Command" }, // 64-bit when access via MSR
    { 0x31, ACCESS_RW, MODE_MMIO, 4, "Interrupt Command High" },
    { 0x32, ACCESS_RW, MODE_BOTH, 4, "LVT Timer" },
    { 0x33, ACCESS_RW, MODE_BOTH, 4, "LVT Thermal Sensor" },
    { 0x34, ACCESS_RW, MODE_BOTH, 4, "LVT Perf Monitoring" },
    { 0x35, ACCESS_RW, MODE_BOTH, 4, "LVT LINT0" },
    { 0x36, ACCESS_RW, MODE_BOTH, 4, "LVT LINT1" },
    { 0x37, ACCESS_RW, MODE_BOTH, 4, "LVT Error" },
    { 0x38, ACCESS_RW, MODE_BOTH, 4, "Initial counter" },
    { 0x39, ACCESS_RO, MODE_BOTH, 4, "Current counter" },
    { 0x3A, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x3B, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x3C, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x3D, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x3E, ACCESS_RW, MODE_BOTH, 4, "Divide Configuration" },
    { 0x3F, NO_ACCESS, MODE_NO,   0, NULL },
    { 0x40, ACCESS_WO, MODE_MSR, 4, "Self IPI" }
};

void (*lapic_mode_switch_transitions[3][3])(void) =
{
    { NULL,               lapic_mode_enable_from_disabled, lapic_mode_x2_from_disabled},
    { lapic_mode_disable, NULL,                            lapic_mode_x2_from_enabled },
    { lapic_mode_disable, lapic_mode_enable_from_x2,       NULL                       }
};
#endif


/*
 *  FUNCTION : local_apic_is_x2apic_supported()
 *  PURPOSE  : Checks if x2APIC mode is supported by CPU
 *  ARGUMENTS: void
 *  RETURNS  : TRUE if supported, FALSE otherwise
 */
BOOLEAN local_apic_is_x2apic_supported(void)
{
    CPUID_PARAMS    cpuid_params;
    cpuid_params.m_rax = 1;
    hw_cpuid(&cpuid_params);
    return BIT_GET64(cpuid_params.m_rcx, CPUID_X2APIC_SUPPORTED_BIT) != 0;
}

/*
 *  FUNCTION : local_apic_discover_mode()
 *  PURPOSE  : Checks Local APIC current mode
 *  ARGUMENTS: void
 *  RETURNS  : LOCAL_APIC_MODE mode discovered
 */
LOCAL_APIC_MODE local_apic_discover_mode(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);
    LOCAL_APIC_MODE mode;

    if (0 != BITMAP_GET(value, IA32_APIC_BASE_MSR_X2APIC_ENABLE))
        mode = LOCAL_APIC_X2_ENABLED;
    else if (0 != BITMAP_GET(value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE))
        mode = LOCAL_APIC_ENABLED;
    else
        mode = LOCAL_APIC_DISABLED;
    return mode;
}
#ifdef INCLUDE_UNUSED_CODE
void lapic_mode_disable(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);
    BITMAP_CLR(value, IA32_APIC_BASE_MSR_X2APIC_ENABLE | IA32_APIC_BASE_MSR_GLOBAL_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
}

void lapic_mode_enable_from_disabled(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);
    BITMAP_SET(value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
}

void lapic_mode_enable_from_x2(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);
    // disable x2 and xAPIC
    BITMAP_CLR(value, IA32_APIC_BASE_MSR_X2APIC_ENABLE | IA32_APIC_BASE_MSR_GLOBAL_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
    // enable xAPIC
    BITMAP_SET(value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
}

void lapic_mode_x2_from_disabled(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);

    BITMAP_SET(value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);

    BITMAP_SET(value, IA32_APIC_BASE_MSR_X2APIC_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
}

void lapic_mode_x2_from_enabled(void)
{
    UINT64 value = hw_read_msr(IA32_MSR_APIC_BASE);
    BITMAP_SET(value, IA32_APIC_BASE_MSR_X2APIC_ENABLE);
    hw_write_msr(IA32_MSR_APIC_BASE, value);
}

/*
 *  FUNCTION : local_apic_set_mode()
 *  PURPOSE  : Set one of 3 possible modes
 *  ARGUMENTS: LOCAL_APIC_MODE mode - mode to set
 *  RETURNS  : LOCAL_APIC_NOERROR if OK, error code otherwise
 */
LOCAL_APIC_ERRNO local_apic_set_mode(LOCAL_APIC_MODE new_mode)
{
    LOCAL_APIC_ERRNO error    = LOCAL_APIC_NOERROR;
    LOCAL_APIC_PER_CPU_DATA*  data = GET_CPU_LAPIC();
    LOCAL_APIC_MODE  old_mode = data->lapic_mode;

    switch (new_mode) {
    case LOCAL_APIC_DISABLED:
    case LOCAL_APIC_ENABLED:
        if (NULL != lapic_mode_switch_transitions[old_mode][new_mode])
            lapic_mode_switch_transitions[old_mode][new_mode]();
        break;

    case LOCAL_APIC_X2_ENABLED:
        if (NULL != lapic_mode_switch_transitions[old_mode][new_mode]) {
            if (TRUE == local_apic_is_x2apic_supported())
                lapic_mode_switch_transitions[old_mode][new_mode]();
            else
                error = LOCAL_APIC_X2_NOT_SUPPORTED;
        }

    default:
        VMM_ASSERT(0);
        break;
    }

    lapic_fill_current_mode( data );

    return error;
}
#endif

static void lapic_fill_current_mode( LOCAL_APIC_PER_CPU_DATA* lapic_data )
{
    lapic_data->lapic_mode = local_apic_discover_mode();

    switch (lapic_data->lapic_mode) {
        case LOCAL_APIC_X2_ENABLED:
            lapic_data->lapic_read_reg = lapic_read_reg_msr;
            lapic_data->lapic_write_reg = lapic_write_reg_msr;
            break;
        case LOCAL_APIC_ENABLED:
            // SW-disabled is HW-enabled also
            lapic_data->lapic_read_reg = lapic_read_reg_mmio;
            lapic_data->lapic_write_reg = lapic_write_reg_mmio;
            break;

        case LOCAL_APIC_DISABLED:
        default:
            VMM_LOG(mask_anonymous, level_trace,"Setting Local APIC into HW-disabled state on CPU#%d\n", hw_cpu_id());
            // BEFORE_VMLAUNCH. This case should not occur.
            VMM_ASSERT( FALSE );
    }

}
void lapic_read_reg_mmio(const LOCAL_APIC_PER_CPU_DATA* data,
                         LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned not_used  UNUSED)
{
    *(UINT32 *) p_data = *(volatile UINT32 *) LOCAL_APIC_REG_ADDRESS(data, reg_id);
}

void lapic_write_reg_mmio(const LOCAL_APIC_PER_CPU_DATA* data,
                          LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned not_used  UNUSED)
{
    *(volatile UINT32 *) LOCAL_APIC_REG_ADDRESS(data, reg_id) = *(UINT32 *) p_data;
}

void lapic_read_reg_msr(const LOCAL_APIC_PER_CPU_DATA* data UNUSED,
                        LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned bytes)
{
    UINT64 value;

    value = hw_read_msr(LOCAL_APIC_REG_MSR(reg_id));
    if (4 == bytes) {
        *(UINT32 *) p_data = (UINT32) value;
    }
    else {
        *(UINT64 *) p_data = value;
    }

}

void lapic_write_reg_msr(const LOCAL_APIC_PER_CPU_DATA* data UNUSED,
                         LOCAL_APIC_REG_ID reg_id, void *p_data, unsigned bytes)
{
    if (4 == bytes) {
        hw_write_msr(LOCAL_APIC_REG_MSR(reg_id), *(UINT32 *) p_data);
    }
    else {
        hw_write_msr(LOCAL_APIC_REG_MSR(reg_id), *(UINT64 *) p_data);
    }
}

#ifdef INCLUDE_UNUSED_CODE
LOCAL_APIC_ERRNO local_apic_access(
    LOCAL_APIC_REG_ID    reg_id,
    RW_ACCESS       rw_access,
    void           *data,
    INT32           bytes_to_deliver,
    INT32          *p_bytes_delivered
    )
    {
    LOCAL_APIC_PER_CPU_DATA *lapic_data = GET_CPU_LAPIC();

    VMM_ASSERT(bytes_to_deliver > 0);
    VMM_ASSERT(WRITE_ACCESS == rw_access || READ_ACCESS == rw_access);

    if (NULL != p_bytes_delivered)
        *p_bytes_delivered = 0;


    // validate arguments
    if (reg_id >= NELEMENTS(lapic_registers)) {
        return LOCAL_APIC_INVALID_REGISTER_ERROR;
    }

    if (0 == (lapic_registers[reg_id].access & ACCESS_RW)) {
        return LOCAL_APIC_RESERVED_REGISTER_ERROR;
    }

    if (0 == (lapic_registers[reg_id].access & rw_access)) {
        return LOCAL_APIC_INVALID_RW_ACCESS_ERROR;
    }

    switch (lapic_data->lapic_mode) {
    case LOCAL_APIC_ENABLED:
        if (0 == BITMAP_GET(lapic_registers[reg_id].modes, MODE_MMIO)) {
            return LOCAL_APIC_REGISTER_MMIO_ACCESS_DISABLED_ERROR;
        }

        if (bytes_to_deliver < (INT32)sizeof(UINT32)) {
            return LOCAL_APIC_REGISTER_ACCESS_LENGTH_ERROR;
        }
        bytes_to_deliver = sizeof(UINT32);
        break;

    case LOCAL_APIC_X2_ENABLED:
        if (0 == BITMAP_GET(lapic_registers[reg_id].modes, MODE_MSR)) {
            return LOCAL_APIC_REGISTER_MSR_ACCESS_DISABLED_ERROR;
        }

        if (bytes_to_deliver < lapic_registers[reg_id].x2_size) {
            return LOCAL_APIC_REGISTER_ACCESS_LENGTH_ERROR;
        }
        bytes_to_deliver = lapic_registers[reg_id].x2_size;
        break;

    default:
        return LOCAL_APIC_ACCESS_WHILE_DISABLED_ERROR;
    }


    switch (rw_access)
    {
    case READ_ACCESS:
        lapic_data->lapic_read_reg(lapic_data, reg_id, data, bytes_to_deliver);
        break;

    case WRITE_ACCESS:
        lapic_data->lapic_write_reg(lapic_data, reg_id, data, bytes_to_deliver);
        break;

    default:
        return LOCAL_APIC_INVALID_RW_ACCESS_ERROR;
    }

    if (NULL != p_bytes_delivered)
        *p_bytes_delivered = bytes_to_deliver;

    return LOCAL_APIC_NOERROR;

    }
#endif

BOOLEAN validate_APIC_BASE_change(UINT64 msr_value)
{
    LOCAL_APIC_PER_CPU_DATA *lapic_data = GET_CPU_LAPIC();
    UINT64 physical_address_size_mask = ~((((UINT64)1) << ((UINT8)hw_read_address_size()))-1);
    UINT64 bit_9_mask = (UINT64)1 << 9;
    UINT64 last_byte_mask = 0xff;
    UINT64 reserved_bits_mask;

    if(local_apic_is_x2apic_supported())
        reserved_bits_mask = bit_9_mask + last_byte_mask + ~((((UINT64)1) << 36)-1)
                    + IA32_APIC_BASE_MSR_BSP;
    else
        reserved_bits_mask = physical_address_size_mask + bit_9_mask + last_byte_mask 
                    + IA32_APIC_BASE_MSR_X2APIC_ENABLE + IA32_APIC_BASE_MSR_BSP;

    //if reserved bits are being changed, return FALSE, so,the caller will inject gp.
    if( (hw_read_msr(IA32_MSR_APIC_BASE) & reserved_bits_mask) != (msr_value & reserved_bits_mask) )
        return FALSE;

    //if the current mode is xAPIC, the legal target modes are xAPIC, x2APIC and disabled state.
    //let's reject any change to disabled state since uVMM relies on xAPIC or x2APIC

    //if the current mode is x2APIC, the legal target modes are x2APIC and disabled state.
    //let's reject any change to disabled state for the same reason
    if( lapic_data->lapic_mode == LOCAL_APIC_X2_ENABLED ) {
        if( !(BITMAP_GET(msr_value, IA32_APIC_BASE_MSR_X2APIC_ENABLE)) ||
            !(BITMAP_GET(msr_value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE)) )
            //VMM_DEADLOOP();
            return FALSE; //inject gp instead of deadloop--recommended by validation guys
    }
    else {
        if( lapic_data->lapic_mode != LOCAL_APIC_ENABLED )
            //VMM_DEADLOOP();
            return FALSE; //inject gp instead of deadloop--recommended by validation guys

        if(!(BITMAP_GET(msr_value, IA32_APIC_BASE_MSR_GLOBAL_ENABLE)))
            //VMM_DEADLOOP();
            return FALSE; //inject gp instead of deadloop--recommended by validation guys
    }

        return TRUE;
}

void local_apic_setup_changed(void)
{
    LOCAL_APIC_PER_CPU_DATA *lapic_data = GET_CPU_LAPIC();
    BOOLEAN                  result;

    lapic_data->lapic_base_address_hpa = hw_read_msr(IA32_MSR_APIC_BASE);
    lapic_data->lapic_base_address_hpa =
    ALIGN_BACKWARD(lapic_data->lapic_base_address_hpa, PAGE_4KB_SIZE);

    lapic_fill_current_mode( lapic_data );
    if( lapic_data->lapic_mode != LOCAL_APIC_X2_ENABLED ) {
        result = hmm_map_uc_physical_page( lapic_data->lapic_base_address_hpa,
                             TRUE /* writable */, FALSE /* not_executable */,
                             FALSE /* do synch with other CPUs to avoid loop back*/,
                             &(lapic_data->lapic_base_address_hva));
        // BEFORE_VMLAUNCH. Critical check, keep it.
        VMM_ASSERT(result);
    }

    VMM_LOG(mask_anonymous, level_trace,"CPU#%d: local apic base = %p\r\n", hw_cpu_id(), lapic_data->lapic_base_address_hpa);

    // We do not unmap previous mapping, so old pages will remain mapped uncachable
}
#ifdef INCLUDE_UNUSED_CODE
ADDRESS lapic_base_address_hpa(void)
{
    return GET_CPU_LAPIC()->lapic_base_address_hpa;
}

ADDRESS lapic_base_address_hva(void)
{
    return GET_CPU_LAPIC()->lapic_base_address_hva;
}
#endif


// update lapic cpu id. (must be called after S3 or  Local APIC host base was changed per cpu)
BOOLEAN update_lapic_cpu_id(void)
{
    LOCAL_APIC_PER_CPU_DATA *lapic_data = GET_CPU_LAPIC();

    // BEFORE_VMLAUNCH. Critical check, keep it.
    VMM_ASSERT(lapic_data);

    lapic_data->lapic_cpu_id = local_apic_get_current_id();

    return TRUE;   
}


BOOLEAN local_apic_cpu_init(void)
{
    local_apic_setup_changed();
    update_lapic_cpu_id();
    return TRUE;
}

BOOLEAN local_apic_init( UINT16 num_of_cpus )
{
    UINT32 chunk_size = num_of_cpus * sizeof( LOCAL_APIC_PER_CPU_DATA );
    if (lapic_cpu_data == 0) {
        lapic_cpu_data = vmm_page_alloc( PAGE_ROUNDUP( chunk_size ));
        VMM_ASSERT( lapic_cpu_data != NULL );
        vmm_memset( lapic_cpu_data, 0, chunk_size );
    }

    return TRUE;
}

/*
 *      Specific IPI support
 */

static void local_apic_wait_for_ipi_delivery( LOCAL_APIC_PER_CPU_DATA* lapic_data )
{
    LOCAL_APIC_INTERRUPT_COMMAND_REGISTER_LOW  icr_low;

    //delivery status bit does not exist for x2APIC mode
    if( lapic_data->lapic_mode != LOCAL_APIC_X2_ENABLED )
    while(TRUE) {
        lapic_data->lapic_read_reg( lapic_data,
                                    LOCAL_APIC_INTERRUPT_COMMAND_REG,
                                    &icr_low.uint32,
                                    sizeof(icr_low.uint32) );

        if(IPI_DELIVERY_STATUS_IDLE == icr_low.bits.delivery_status) {
            break;
        }
    }
}

BOOLEAN local_apic_ipi_verify_params(LOCAL_APIC_IPI_DESTINATION_SHORTHAND dst_shorthand,
                             LOCAL_APIC_IPI_DELIVERY_MODE delivery_mode,
                             UINT8  vector, LOCAL_APIC_IPI_LEVEL level,
                             LOCAL_APIC_IPI_TRIGGER_MODE trigger_mode)
{
    BOOLEAN success = TRUE;

    if(dst_shorthand == IPI_DST_SELF && (delivery_mode == IPI_DELIVERY_MODE_LOWEST_PRIORITY
        || delivery_mode == IPI_DELIVERY_MODE_NMI || delivery_mode == IPI_DELIVERY_MODE_INIT
        || delivery_mode == IPI_DELIVERY_MODE_SMI || delivery_mode == IPI_DELIVERY_MODE_START_UP)) {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: dst_shorthand == IPI_DST_SELF && delivery_mode==" STRINGIFY(delivery_mode)"\r\n");
    }

    if(dst_shorthand == IPI_DST_ALL_INCLUDING_SELF &&
       (delivery_mode == IPI_DELIVERY_MODE_LOWEST_PRIORITY
        || delivery_mode == IPI_DELIVERY_MODE_NMI || delivery_mode == IPI_DELIVERY_MODE_INIT
        || delivery_mode == IPI_DELIVERY_MODE_SMI || delivery_mode == IPI_DELIVERY_MODE_START_UP)) {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: dst_shorthand == IPI_DST_ALL_INCLUDING_SELF && delivery_mode==" STRINGIFY(delivery_mode)"\r\n");
    }

    if(trigger_mode == IPI_DELIVERY_TRIGGER_MODE_LEVEL &&
       (delivery_mode == IPI_DELIVERY_MODE_SMI || delivery_mode == IPI_DELIVERY_MODE_START_UP)) {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: trigger_mode == IPI_DELIVERY_TRIGGER_MODE_LEVEL && delivery_mode==" STRINGIFY(delivery_mode)"\r\n");
    }

    if((delivery_mode == IPI_DELIVERY_MODE_SMI || delivery_mode == IPI_DELIVERY_MODE_INIT)
        && vector != 0) {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: delivery_mode == " STRINGIFY(delivery_mode)", vector must be zero\r\n");
    }

    // init level de-assert
    if(delivery_mode == IPI_DELIVERY_MODE_INIT && level == IPI_DELIVERY_LEVEL_DEASSERT && trigger_mode ==IPI_DELIVERY_TRIGGER_MODE_LEVEL
        && dst_shorthand != IPI_DST_ALL_INCLUDING_SELF)
    {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: init level deassert ipi - destination must be IPI_DST_ALL_INCLUDING_SELF\r\n");
    }

    // level must be assert for ipis other than init level de-assert
    if((delivery_mode != IPI_DELIVERY_MODE_INIT || trigger_mode !=IPI_DELIVERY_TRIGGER_MODE_LEVEL) && level == IPI_DELIVERY_LEVEL_DEASSERT)
    {
        success = FALSE;
        VMM_LOG(mask_anonymous, level_trace,"IPI params verification failed: level must be ASSERT for all ipis except init level deassert ipi\r\n");
    }

    return success;
}

BOOLEAN
local_apic_send_ipi(LOCAL_APIC_IPI_DESTINATION_SHORTHAND dst_shorthand,
                             UINT8  dst,
                             LOCAL_APIC_IPI_DESTINATION_MODE dst_mode,
                             LOCAL_APIC_IPI_DELIVERY_MODE delivery_mode,
                             UINT8  vector,
                             LOCAL_APIC_IPI_LEVEL level,
                             LOCAL_APIC_IPI_TRIGGER_MODE trigger_mode)
{
    LOCAL_APIC_INTERRUPT_COMMAND_REGISTER icr;
    UINT32                                icr_high_save;
    LOCAL_APIC_PER_CPU_DATA*              lapic_data = GET_CPU_LAPIC();
    BOOLEAN params_valid = FALSE;


    params_valid = local_apic_ipi_verify_params(dst_shorthand, delivery_mode , vector, level, trigger_mode);

    if(! params_valid) {
        return FALSE;
    }

    // wait for IPI in progress to finish
    local_apic_wait_for_ipi_delivery(lapic_data);

    icr.hi_dword.uint32 = 0;

    if (IPI_DST_NO_SHORTHAND == dst_shorthand) {
        LOCAL_APIC_PER_CPU_DATA *dst_lapic_data = GET_OTHER_LAPIC(dst);
        icr.hi_dword.bits.destination = dst_lapic_data->lapic_cpu_id;
    }
    else if (IPI_DST_SELF == dst_shorthand) {
        icr.hi_dword.bits.destination = lapic_data->lapic_cpu_id;
    }
    else {
        icr.hi_dword.bits.destination = dst;
    }

        if( lapic_data->lapic_mode == LOCAL_APIC_X2_ENABLED )
                icr.hi_dword.uint32 = (UINT32)icr.hi_dword.bits.destination;

    icr.lo_dword.uint32 = 0;
    icr.lo_dword.bits.destination_shorthand = dst_shorthand;
    icr.lo_dword.bits.destination_mode = dst_mode;
    icr.lo_dword.bits.delivery_mode = delivery_mode;
    icr.lo_dword.bits.vector = vector;
    icr.lo_dword.bits.level = level;
    icr.lo_dword.bits.trigger_mode = trigger_mode;

    if (LOCAL_APIC_X2_ENABLED == lapic_data->lapic_mode) {
        lapic_data->lapic_write_reg( lapic_data,
                                     LOCAL_APIC_INTERRUPT_COMMAND_REG,
                                     &icr,
                                     sizeof(icr));

        // wait for IPI in progress to finish
        local_apic_wait_for_ipi_delivery(lapic_data);
    }
    else {
        // save previous uint32: if guest is switched in the middle of IPI setup,
        // need to restore the guest IPI destination uint32
        lapic_data->lapic_read_reg(lapic_data, LOCAL_APIC_INTERRUPT_COMMAND_HI_REG,
                                   &icr_high_save, sizeof(icr_high_save));

        // write new destination
        lapic_data->lapic_write_reg(lapic_data, LOCAL_APIC_INTERRUPT_COMMAND_HI_REG,
                                    &icr.hi_dword.uint32, sizeof(icr.hi_dword.uint32));

        // send IPI
        lapic_data->lapic_write_reg(lapic_data, LOCAL_APIC_INTERRUPT_COMMAND_REG,
                                     &icr.lo_dword.uint32, sizeof(icr.lo_dword.uint32));

        // wait for IPI in progress to finish
        local_apic_wait_for_ipi_delivery(lapic_data);

        // restore guest IPI destination
        lapic_data->lapic_write_reg( lapic_data, LOCAL_APIC_INTERRUPT_COMMAND_HI_REG,
                                     &icr_high_save, sizeof(icr_high_save));
    }

    return TRUE;
}

UINT8 local_apic_get_current_id( void )
{
    LOCAL_APIC_PER_CPU_DATA* lapic_data = GET_CPU_LAPIC();
    UINT32  local_apic_id = 0;

    lapic_data->lapic_read_reg( lapic_data,
                                LOCAL_APIC_ID_REG,
                                &local_apic_id,
                                sizeof(local_apic_id));
        
        if( lapic_data->lapic_mode != LOCAL_APIC_X2_ENABLED )
                return (UINT8)(local_apic_id >> LOCAL_APIC_ID_LOW_RESERVED_BITS_COUNT);
        else
                return (UINT8)(local_apic_id);
}
#ifdef INCLUDE_UNUSED_CODE
void local_apic_send_init_to_self( void )
{
    local_apic_send_ipi( IPI_DST_NO_SHORTHAND, (UINT8) hw_cpu_id(),
                         IPI_DESTINATION_MODE_PHYSICAL,
                         IPI_DELIVERY_MODE_INIT,
                         0,
                         IPI_DELIVERY_LEVEL_ASSERT,
                         IPI_DELIVERY_TRIGGER_MODE_EDGE );

    VMM_LOG(mask_anonymous, level_trace,"local_apic_send_init_to_self: local_apic_send_ipi(INIT) returned!!!\n");
    VMM_DEADLOOP();
}
#endif
void local_apic_send_init( CPU_ID dst )
{
    local_apic_send_ipi( IPI_DST_NO_SHORTHAND, (UINT8) dst,
                         IPI_DESTINATION_MODE_PHYSICAL,
                         IPI_DELIVERY_MODE_INIT,
                         0,
                         IPI_DELIVERY_LEVEL_ASSERT,
                         IPI_DELIVERY_TRIGGER_MODE_EDGE );
}

#ifdef DEBUG

LOCAL_APIC_MODE  local_apic_get_mode(void)
{
    return GET_CPU_LAPIC()->lapic_mode;
}
BOOLEAN local_apic_is_sw_enabled(void)
{
    LOCAL_APIC_PER_CPU_DATA* lapic_data = GET_CPU_LAPIC();
    UINT32                   spurious_vector_reg_value = 0;

    if (LOCAL_APIC_DISABLED == lapic_data->lapic_mode) {
        return FALSE;
    }

    // now read the spurios register
    lapic_data->lapic_read_reg( lapic_data,
                                LOCAL_APIC_SPURIOUS_INTR_VECTOR_REG,
                                &spurious_vector_reg_value,
                                sizeof(spurious_vector_reg_value));
    return BIT_GET(spurious_vector_reg_value, IA32_APIC_SW_ENABLE_BIT_IDX) ? TRUE : FALSE;
}

// find highest set bit in 256bit reg (8 sequential regs 32bit each). 
// Return UINT32_ALL_ONES if no 1s found.
static UINT32 find_highest_bit_in_reg(LOCAL_APIC_PER_CPU_DATA* lapic_data, LOCAL_APIC_REG_ID reg_id,
                                       UINT32 reg_size_32bit_units )
{
    UINT32 subreg_idx;
    UINT32 subreg_value;
    UINT32 bit_idx;

    for (subreg_idx = reg_size_32bit_units; subreg_idx > 0; --subreg_idx) {
        lapic_data->lapic_read_reg( lapic_data, reg_id + subreg_idx - 1,
                                    &subreg_value, sizeof(subreg_value));

        if (0 == subreg_value) {
            continue;
        }

        // find highest set bit
        hw_scan_bit_backward( &bit_idx, subreg_value );

        return ((subreg_idx - 1)* sizeof(subreg_value) * 8 + bit_idx);
    }

    // if we are here - not found
    return UINT32_ALL_ONES;
}
// Find maximum interrupt request register priority
// IRR priority is a upper 4bit value of the highest interrupt bit set to 1
static UINT32 local_apic_get_irr_priority( LOCAL_APIC_PER_CPU_DATA* lapic_data )
{
    UINT32 irr_max_vector = find_highest_bit_in_reg(
                        lapic_data,
                        LOCAL_APIC_INTERRUPT_REQUEST_REG,
                        8 );

    return (irr_max_vector == UINT32_ALL_ONES) ? 0 : ((irr_max_vector >> 4) & 0xF);
}

// Processor Priority Register is a read-only register set to the highest priority
// class between ISR priority (priority of the highest ISR vector) and TPR
//   PPR = MAX( ISR, TPR )
static UINT32 local_apic_get_processor_priority( LOCAL_APIC_PER_CPU_DATA* lapic_data )
{
    UINT32 ppr_value;

    lapic_data->lapic_read_reg( lapic_data, LOCAL_APIC_PROCESSOR_PRIORITY_REG,
                                &ppr_value, sizeof(ppr_value));
    return ((ppr_value >> 4) & 0xF);
}

// Test for ready-to-be-accepted fixed interrupts.
// Fixed interrupt is ready to be accepted if Local APIC will inject interrupt when
// SW will enable interrupts (assuming NMI is not in-service and no other
// execution-based interrupt blocking is active)
// Fixed Interrupt is ready-to-be-accepted if
//   IRR_Priority > Processor_Priority
BOOLEAN local_apic_is_ready_interrupt_exist(void)
{
    LOCAL_APIC_PER_CPU_DATA* lapic_data = GET_CPU_LAPIC();

    VMM_ASSERT( local_apic_is_sw_enabled() == TRUE );
    return local_apic_get_irr_priority(lapic_data) > local_apic_get_processor_priority(lapic_data);
}
#endif
