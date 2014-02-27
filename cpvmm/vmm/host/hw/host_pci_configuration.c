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

#include "host_pci_configuration.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "libc.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(HOST_PCI_CONFIGURATION_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(HOST_PCI_CONFIGURATION_C, __condition)

#define PCI_DEV_INDEX_INVALID   0 // index 0 is not in use. used to specify "invalid" in lookup table

// bit 7: =0 single function, =1 multi-function
#define PCI_IS_MULTIFUNCTION_DEVICE(header_type) (((header_type) & 0x80) != 0)
#define PCI_IS_PCI_2_PCI_BRIDGE(base_class, sub_class) ((base_class) == PCI_BASE_CLASS_BRIDGE && (sub_class) == 0x04)
#ifdef PCI_SCAN
static HOST_PCI_DEVICE pci_devices[PCI_MAX_NUM_SUPPORTED_DEVICES + 1];
static PCI_DEV_INDEX avail_pci_device_index = 1; // index 0 is not in use. used to specify "invalid" in lookup table
static PCI_DEV_INDEX pci_devices_lookup_table[PCI_MAX_NUM_FUNCTIONS];
static UINT32 num_pci_devices = 0;

UINT8 pci_read8(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    return hw_read_port_8(PCI_CONFIG_DATA_REGISTER | (addr.Uint32 & 0x3));
}

void pci_write8(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg, UINT8 value)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    hw_write_port_8(PCI_CONFIG_DATA_REGISTER | (addr.Uint32 & 0x3), value);
}

UINT16 pci_read16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    return hw_read_port_16(PCI_CONFIG_DATA_REGISTER | (addr.Uint32 & 0x3));
}

void pci_write16(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg, UINT16 value)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    hw_write_port_16(PCI_CONFIG_DATA_REGISTER | (addr.Uint32 & 0x2), value);
}

UINT32 pci_read32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    return hw_read_port_32(PCI_CONFIG_DATA_REGISTER);
}

void pci_write32(UINT8 bus, UINT8 device, UINT8 function, UINT8 reg, UINT32 value)
{
    PCI_CONFIG_ADDRESS addr;

    addr.Uint32 = 0;
    addr.Bits.Bus = bus;
    addr.Bits.Device = device;
    addr.Bits.Function = function;
    addr.Bits.Register = reg;
    addr.Bits.Enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.Uint32 & ~0x3);
    hw_write_port_32(PCI_CONFIG_DATA_REGISTER, value);
}

HOST_PCI_DEVICE *get_host_pci_device(UINT8 bus, UINT8 device, UINT8 function)
{
    HOST_PCI_DEVICE *pci_dev;
    PCI_DEVICE_ADDRESS lookup_table_index = 0;
    PCI_DEV_INDEX pci_dev_index = 0;

    if(FALSE == PCI_IS_ADDRESS_VALID(bus, device, function))
    {
        return NULL;
    }
    SET_PCI_BUS(lookup_table_index, bus);
    SET_PCI_DEVICE(lookup_table_index, device);
    SET_PCI_FUNCTION(lookup_table_index, function);
    pci_dev_index = pci_devices_lookup_table[lookup_table_index];

    if(PCI_DEV_INDEX_INVALID == pci_dev_index) {
        pci_dev = NULL;
    }
    else {
        pci_dev = &pci_devices[pci_dev_index];
    }
    return pci_dev;
}

BOOLEAN pci_read_secondary_bus_reg(UINT8 bus, UINT8 device, UINT8 func, OUT UINT8 *secondary_bus)
{
    HOST_PCI_DEVICE *pci_bridge = get_host_pci_device(bus, device, func);

    *secondary_bus = 0;
    if(NULL == pci_bridge || FALSE == pci_bridge->is_pci_2_pci_bridge
       || PCI_CONFIG_HEADER_TYPE_PCI2PCI_BRIDGE != pci_bridge->header_type) {
        return FALSE;
    }

    *secondary_bus = pci_read8(bus, device, func, PCI_CONFIG_SECONDARY_BUS_OFFSET);
    return TRUE;
}

static UINT8
host_pci_decode_bar(
    UINT8  bus,
    UINT8  device,
    UINT8  function,
    UINT8  bar_offset,
    PCI_BASE_ADDRESS_REGISTER *bar)
{
    UINT32 bar_value_low = pci_read32(bus, device, function, bar_offset);
    UINT32 bar_value_high = 0;
    UINT64 bar_value = 0;
    UINT32 encoded_size_low = 0;
    UINT32 encoded_size_high = 0;
    UINT64 encoded_size = 0;
    UINT64 mask;
    UINT32 address_type = PCI_CONFIG_HEADER_BAR_ADDRESS_32;

    VMM_LOG(mask_anonymous, level_trace,"%s %d:%d:%d:%d, bar_value_low=0x%x\r\n",
                    __FUNCTION__, bus, device, function, bar_offset, bar_value_low);

    if (bar_value_low > 1) // 0: not used mmio space; 1: not used io space
    {
        // issue size determination command
        pci_write32(bus, device, function, bar_offset, PCI_CONFIG_HEADER_BAR_SIZING_COMMAND);
        encoded_size_low = pci_read32(bus, device, function, bar_offset);

        bar->type = bar_value_low & PCI_CONFIG_HEADER_BAR_MEMORY_TYPE_MASK;

        mask = (PCI_BAR_IO_REGION == bar->type) ?
          PCI_CONFIG_HEADER_BAR_ADDRESS_MASK_TYPE_IO :
          PCI_CONFIG_HEADER_BAR_ADDRESS_MASK_TYPE_MMIO;

        // valid only for mmio
        address_type = (UINT32)(bar_value_low & PCI_CONFIG_HEADER_BAR_ADDRESS_TYPE_MASK) >> 1;

        if(bar->type == PCI_BAR_MMIO_REGION && address_type == PCI_CONFIG_HEADER_BAR_ADDRESS_64) {
            // issue size determination command
            bar_value_high = pci_read32(bus, device, function, bar_offset + 4);
            pci_write32(bus, device, function, bar_offset + 4, PCI_CONFIG_HEADER_BAR_SIZING_COMMAND);
            encoded_size_high = pci_read32(bus, device, function, bar_offset + 4);
            bar_value = (UINT64) bar_value_high << 32 | ((UINT64)bar_value_low & 0x00000000FFFFFFFF);
            bar->addr = bar_value & mask;
            encoded_size = (UINT64) encoded_size_high << 32 | ((UINT64)encoded_size_low & 0x00000000FFFFFFFF);
            encoded_size &= mask;
            bar->length = (~encoded_size) + 1;
            pci_write32(bus, device, function, bar_offset, bar_value_low); // restore original value
            pci_write32(bus, device, function, bar_offset + 4, bar_value_high); // restore original value
        }
        else {
            bar->addr = ((UINT64)bar_value_low & 0x00000000FFFFFFFF) & mask;
            encoded_size = 0xFFFFFFFF00000000 | ((UINT64)encoded_size_low & 0x00000000FFFFFFFF);
            encoded_size &= mask;
            bar->length = (~encoded_size) + 1;
            pci_write32(bus, device, function, bar_offset, bar_value_low); // restore original value
        }

        if (PCI_BAR_IO_REGION == bar->type) {
            bar->length &= 0xFFFF; // IO space in Intel  arch can't exceed 64K bytes
        }
    }
    else {
        bar->type = PCI_BAR_UNUSED;
    }
    return (address_type == PCI_CONFIG_HEADER_BAR_ADDRESS_64) ? 8 : 4;
}

static void host_pci_decode_pci_bridge(
    UINT8  bus,
    UINT8  device,
    UINT8  function,
    PCI_BASE_ADDRESS_REGISTER *bar_mmio,
    PCI_BASE_ADDRESS_REGISTER *bar_io)
{
    UINT32 memory_base = ((UINT32)pci_read16(bus, device, function, PCI_CONFIG_BRIDGE_MEMORY_BASE) << 16) & 0xFFF00000;
    UINT32 memory_limit = ((UINT32)pci_read16(bus, device, function, PCI_CONFIG_BRIDGE_MEMORY_LIMIT) << 16) | 0x000FFFFF;
    UINT8 io_base_low = pci_read8(bus, device, function, PCI_CONFIG_BRIDGE_IO_BASE_LOW);
    UINT8 io_limit_low = pci_read8(bus, device, function, PCI_CONFIG_BRIDGE_IO_LIMIT_LOW);
    UINT16 io_base_high = 0;
    UINT16 io_limit_high = 0;
    UINT64 io_base;
    UINT64 io_limit;

    // mmio
    if (memory_limit < memory_base) {
        bar_mmio->type = PCI_BAR_UNUSED;
    }
    else {
        bar_mmio->type = PCI_BAR_MMIO_REGION;
        bar_mmio->addr = (UINT64)memory_base & 0x00000000FFFFFFFF;
        bar_mmio->length = (UINT64)(memory_limit - memory_base +1) & 0x00000000FFFFFFFF;
    }

    // io
    if (io_base_low == 0 || io_limit_low == 0 || io_limit_low < io_base_low) {
        bar_io->type = PCI_BAR_UNUSED;
    }
    else if ((io_base_low & 0xF) > 1) {
        bar_io->type = PCI_BAR_UNUSED;
        VMM_LOG(mask_anonymous, level_print_always,"%s Warning: reserved IO address capability in bridge (%d:%d:%d) detected, io_base_low=0x%x\r\n",
                    __FUNCTION__, bus, device, function, io_base_low);
    }
    else {
        if ((io_base_low & 0xF) == 1) // 32 bit IO address {
            // update the high 16 bits
            io_base_high = pci_read16(bus, device, function, PCI_CONFIG_BRIDGE_IO_BASE_HIGH);
            io_limit_high = pci_read16(bus, device, function, PCI_CONFIG_BRIDGE_IO_LIMIT_HIGH);
        }
        io_base = (((UINT64) io_base_high << 16) & 0x00000000FFFF0000) |
                      (((UINT64) io_base_low << 8) & 0x000000000000F000);
        io_limit = (((UINT64) io_limit_high << 16) & 0x00000000FFFF0000) |
                      (((UINT64) io_limit_low << 8) & 0x000000000000F000) |
                      0x0000000000000FFF;
        bar_io->type = PCI_BAR_IO_REGION;
        bar_io->addr = io_base;
        bar_io->length = io_limit-io_base+1;
    }
}

static void pci_init_device(PCI_DEVICE_ADDRESS device_addr, 
                            PCI_DEVICE_ADDRESS parent_addr, 
                            BOOLEAN parent_addr_valid,
                            BOOLEAN is_bridge)
{
    HOST_PCI_DEVICE *pci_dev;
    PCI_DEV_INDEX pci_dev_index = 0;
    UINT32 i;
    UINT8 bus, device, function;
    UINT8 bar_offset;

    // BEFORE_VMLAUNCH
    VMM_ASSERT(avail_pci_device_index <= PCI_MAX_NUM_SUPPORTED_DEVICES);

    pci_dev_index = pci_devices_lookup_table[device_addr];

    if(PCI_DEV_INDEX_INVALID != pci_dev_index) {// already initialized
        return;
    }

    num_pci_devices++;
    pci_dev_index = avail_pci_device_index++;
    pci_devices_lookup_table[device_addr] = pci_dev_index;

    pci_dev = &pci_devices[pci_dev_index];
    pci_dev->address = device_addr;
    bus = GET_PCI_BUS(device_addr);
    device = GET_PCI_DEVICE(device_addr);
    function = GET_PCI_FUNCTION(device_addr);
    pci_dev->vendor_id = pci_read16(bus, device, function, PCI_CONFIG_VENDOR_ID_OFFSET);
    pci_dev->device_id = pci_read16(bus, device, function, PCI_CONFIG_DEVICE_ID_OFFSET);
    pci_dev->revision_id = pci_read8(bus, device, function, PCI_CONFIG_REVISION_ID_OFFSET);
    pci_dev->base_class = pci_read8(bus, device, function, PCI_CONFIG_BASE_CLASS_CODE_OFFSET);
    pci_dev->sub_class = pci_read8(bus, device, function, PCI_CONFIG_SUB_CLASS_CODE_OFFSET);
    pci_dev->programming_interface = pci_read8(bus, device, function, PCI_CONFIG_PROGRAMMING_INTERFACE_OFFSET);
    pci_dev->header_type = pci_read8(bus, device, 0, PCI_CONFIG_HEADER_TYPE_OFFSET);
    pci_dev->is_multifunction = PCI_IS_MULTIFUNCTION_DEVICE(pci_dev->header_type);
    pci_dev->header_type = pci_dev->header_type & ~0x80; // clear multifunction bit
    pci_dev->is_pci_2_pci_bridge = PCI_IS_PCI_2_PCI_BRIDGE(pci_dev->base_class, pci_dev->sub_class);
    pci_dev->interrupt_pin = pci_read8(bus, device, function, PCI_CONFIG_INTERRUPT_PIN_OFFSET);
    pci_dev->interrupt_line = pci_read8(bus, device, function, PCI_CONFIG_INTERRUPT_LINE_OFFSET);
    if(parent_addr_valid) {
        pci_dev->parent = get_host_pci_device(GET_PCI_BUS(parent_addr), GET_PCI_DEVICE(parent_addr), GET_PCI_FUNCTION(parent_addr));
    }
    else {
        pci_dev->parent = NULL;
    }

    if(pci_dev->parent == NULL) {
        pci_dev->depth = 1;
        pci_dev->path.start_bus = bus;
    }
    else {
        pci_dev->depth = pci_dev->parent->depth + 1;
        pci_dev->path.start_bus = pci_dev->parent->path.start_bus;
        for(i = 0; i < pci_dev->parent->depth; i++)
        {
            pci_dev->path.path[i] = pci_dev->parent->path.path[i];
        }
    }
    VMM_ASSERT(pci_dev->depth <= PCI_MAX_PATH);
    pci_dev->path.path[pci_dev->depth - 1].device = device;
    pci_dev->path.path[pci_dev->depth - 1].function = function;

    bar_offset = PCI_CONFIG_BAR_OFFSET;
    if (is_bridge) {
        for(i = 0; i < PCI_MAX_BAR_NUMBER_IN_BRIDGE; i++) {
            // Assumption: according to PCI bridge spec 1.2, host_pci_decode_bar() will only return 4 (as 32 bit) for bridge
            // 64 bit mapping is not supported in bridge
            bar_offset = bar_offset + host_pci_decode_bar(bus, device, function, bar_offset, &pci_dev->bars[i]);
        }
        host_pci_decode_pci_bridge(bus, device, function, &pci_dev->bars[i], &pci_dev->bars[i+1]); // set io range and mmio range
        i+=2; // for the io bar and mmio bar set by host_pci_decode_pci_bridge() above
        // set rest bars as unused
        for (; i < PCI_MAX_BAR_NUMBER; i++)
            pci_dev->bars[i].type = PCI_BAR_UNUSED;
    }
    else {
        for(i = 0; i < PCI_MAX_BAR_NUMBER; i++) {
            if (bar_offset > PCI_CONFIG_BAR_LAST_OFFSET) // total bar size is 0x10~0x24
                pci_dev->bars[i].type = PCI_BAR_UNUSED;
            else
                bar_offset = bar_offset + host_pci_decode_bar(bus, device, function, bar_offset, &pci_dev->bars[i]);
        }
    }
}


static void pci_scan_bus(UINT8 bus, PCI_DEVICE_ADDRESS parent_addr, BOOLEAN parent_addr_valid)
{
    UINT8 device = 0;
    UINT8 function = 0;
    UINT8 header_type = 0;
    UINT8 max_functions = 0;
    UINT16 vendor_id = 0;
    UINT16 device_id = 0;
    BOOLEAN is_multifunction = 0;
    UINT8 base_class = 0;
    UINT8 sub_class = 0;
    UINT8 secondary_bus = 0;
    PCI_DEVICE_ADDRESS this_device_address = 0;
    BOOLEAN is_bridge;

    for(device = 0; device < PCI_MAX_NUM_DEVICES_ON_BUS; device++) {
        header_type = pci_read8(bus, device, 0, PCI_CONFIG_HEADER_TYPE_OFFSET);
        is_multifunction = PCI_IS_MULTIFUNCTION_DEVICE(header_type); // bit 7: =0 single function, =1 multi-function
        max_functions = is_multifunction ? PCI_MAX_NUM_FUNCTIONS_ON_DEVICE: 1;
        header_type = header_type & ~0x80; // clear multifunction bit

        for(function = 0; function < max_functions; function++) {
            vendor_id = pci_read16(bus, device, function, PCI_CONFIG_VENDOR_ID_OFFSET);
            device_id = pci_read16(bus, device, function, PCI_CONFIG_DEVICE_ID_OFFSET);

            if(PCI_INVALID_VENDOR_ID == vendor_id || PCI_INVALID_DEVICE_ID == device_id) {
                continue;
            }

            SET_PCI_BUS(this_device_address, bus);
            SET_PCI_DEVICE(this_device_address, device);
            SET_PCI_FUNCTION(this_device_address, function);

            base_class = pci_read8(bus, device, function, PCI_CONFIG_BASE_CLASS_CODE_OFFSET);
            sub_class = pci_read8(bus, device, function, PCI_CONFIG_SUB_CLASS_CODE_OFFSET);

            is_bridge = PCI_IS_PCI_2_PCI_BRIDGE(base_class, sub_class);

            // call device handler
            pci_init_device(this_device_address, parent_addr, parent_addr_valid, is_bridge);

            // check if it is needed to go downstream the bridge
            if(is_bridge) {
                if (header_type == 1) // PCI Bridge header type. it should be 1. Skip misconfigured devices {
                    secondary_bus = pci_read8(bus, device, function, PCI_CONFIG_SECONDARY_BUS_OFFSET);
                    pci_scan_bus(secondary_bus, this_device_address, TRUE);
                }
            }
        }
    }
}

UINT32 host_pci_get_num_devices(void)
{
    return num_pci_devices;
}

static void host_pci_print_bar(PCI_BASE_ADDRESS_REGISTER *bar)
{
    static char* bar_type_string = NULL;

    if(PCI_BAR_UNUSED == bar->type) {
        //bar_type_string = "unused";
        return;
    }
    else if(PCI_BAR_IO_REGION == bar->type) {
        bar_type_string = "io";
    }
    else if(PCI_BAR_MMIO_REGION == bar->type) {
        bar_type_string = "mmio";
    }

    VMM_LOG(mask_anonymous, level_trace,"%s addr=%p size=%p; ", bar_type_string, bar->addr, bar->length);
}

#ifdef VMM_DEBUG_SCREEN
static void host_pci_print_bar_screen(PCI_BASE_ADDRESS_REGISTER *bar)
{
    static char* bar_type_string = NULL;

    if(PCI_BAR_UNUSED == bar->type) {
        //bar_type_string = "unused";
        return;
    }
    else if(PCI_BAR_IO_REGION == bar->type) {
        bar_type_string = "io";
    }
    else if(PCI_BAR_MMIO_REGION == bar->type) {
        bar_type_string = "mmio";
    }

    VMM_LOG_SCREEN("%s addr=%p size=%p; ", bar_type_string, bar->addr, bar->length);
}
#endif

static void host_pci_print(void)
{
    UINT32 i = 0, j;
    PCI_DEVICE_ADDRESS device_addr;
    PCI_DEV_INDEX pci_dev_index = 0;
    HOST_PCI_DEVICE *pci_dev;

    VMM_LOG(mask_anonymous, level_trace,"[Bus]    [Dev]    [Func]    [Vendor ID]    [Dev ID]   [PCI-PCI Bridge]\r\n");
    //vmm_clear_screen();
    for(i = 0; i < PCI_MAX_NUM_FUNCTIONS; i++) {
        if(PCI_DEV_INDEX_INVALID == pci_devices_lookup_table[i]) {
            continue;
        }

        device_addr = (UINT16) i;
        pci_dev_index = pci_devices_lookup_table[i];
        pci_dev = &pci_devices[pci_dev_index];
        
        VMM_LOG(mask_anonymous, level_trace,"%5d    %5d    %6d    %#11x    %#8x    ",
             GET_PCI_BUS(device_addr), GET_PCI_DEVICE(device_addr), GET_PCI_FUNCTION(device_addr), pci_dev->vendor_id, pci_dev->device_id);

        if(pci_dev->is_pci_2_pci_bridge) {
            VMM_LOG(mask_anonymous, level_trace,"%16c    ", 'X');
        }
        VMM_LOG(mask_anonymous, level_trace,"\r\n BARs: ");
        for(j = 0; j < PCI_MAX_BAR_NUMBER; j++) {
            host_pci_print_bar(&(pci_dev->bars[j]));
        }
        VMM_LOG(mask_anonymous, level_trace,"\r\n");
    }
}

void host_pci_initialize(void)
{
    UINT16 bus; // use 16 bits instead of 8 to avoid wrap around on bus==256
    PCI_DEVICE_ADDRESS addr = {0};

    vmm_zeromem(pci_devices, sizeof(pci_devices));
    vmm_zeromem(pci_devices_lookup_table, sizeof(pci_devices_lookup_table));

    VMM_LOG(mask_anonymous, level_trace,"\r\nSTART Host PCI scan\r\n");
    for(bus = 0; bus < PCI_MAX_NUM_BUSES; bus++) {
        pci_scan_bus((UINT8) bus, addr, FALSE);
    }
    
    host_pci_print();
    VMM_LOG(mask_anonymous, level_trace,"\r\nEND Host PCI scan\r\n");
}
#endif //PCI_SCAN
