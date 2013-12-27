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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_PCI_CONFIGURATION_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_PCI_CONFIGURATION_C, __condition)
#include "guest_pci_configuration.h"
#include "guest.h"
#include "hash64_api.h"
#include "memory_allocator.h"
#include "list.h"
#include "vmexit_io.h"
#include "guest_cpu.h"
#include "hw_utils.h"
#include "heap.h"
#ifdef PCI_SCAN
#pragma warning (disable:4100)

extern
void io_transparent_read_handler(
    GUEST_CPU_HANDLE    gcpu,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value
    );

extern
void io_transparent_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value
    );

static void apply_default_device_assignment(GUEST_ID guest_id);
static GUEST_PCI_DEVICES* find_guest_devices(GUEST_ID guest_id);
#ifdef INCLUDE_UNUSED_CODE
static GUEST_PCI_DEVICE* find_device(GUEST_ID guest_id, UINT8 bus, UINT8 device, UINT8 function);
#endif
static
void pci_read_hide (GUEST_CPU_HANDLE  gcpu,
                    GUEST_PCI_DEVICE *pci_device,
                    UINT32 port_id,
                    UINT32 port_size,
                    void   *value);
static
void pci_write_hide (GUEST_CPU_HANDLE  gcpu,
                     GUEST_PCI_DEVICE *pci_device,
                     UINT32 port_id,
                     UINT32 port_size,
                     void   *value);

static
void pci_read_passthrough(GUEST_CPU_HANDLE  gcpu,
                          GUEST_PCI_DEVICE * pci_device,
                          UINT32 port_id,
                          UINT32 port_size,
                          void   *value);

static
void pci_write_passthrough(GUEST_CPU_HANDLE  gcpu,
                           GUEST_PCI_DEVICE * pci_device,
                           UINT32 port_id,
                           UINT32 port_size,
                           void   *value);
#ifdef INCLUDE_UNUSED_CODE
static void io_pci_data_handler(GUEST_CPU_HANDLE  gcpu,
                                UINT16            port_id,
                                unsigned          port_size, // 1, 2, 4
                                RW_ACCESS         access,
                                void              *p_value);

static void io_pci_address_handler(GUEST_CPU_HANDLE  gcpu,
                                   UINT16            port_id,
                                   unsigned          port_size, // 1, 2, 4
                                   RW_ACCESS         access,
                                   void              *p_value);
#endif

static LIST_ELEMENT guest_pci_devices[1];
static HASH64_HANDLE device_to_guest = HASH64_INVALID_HANDLE;

static GPCI_GUEST_PROFILE device_owner_guest_profile = {pci_read_passthrough, pci_write_passthrough}; // passthrough
static GPCI_GUEST_PROFILE no_devices_guest_profile = {pci_read_hide, pci_write_hide};

BOOLEAN gpci_initialize(void)
{
    GUEST_HANDLE   guest;
    GUEST_ECONTEXT guest_ctx;

    vmm_zeromem(guest_pci_devices, sizeof(guest_pci_devices));
    list_init(guest_pci_devices);
    device_to_guest = hash64_create_default_hash(256);

    for( guest = guest_first( &guest_ctx ); guest; guest = guest_next( &guest_ctx ))
    {
        gpci_guest_initialize(guest_get_id(guest));
    }

    return TRUE;
}

BOOLEAN gpci_guest_initialize(GUEST_ID guest_id)
{
    GUEST_PCI_DEVICES *gpci = NULL;
//    UINT32 port;

    gpci = (GUEST_PCI_DEVICES *)vmm_memory_alloc(sizeof(GUEST_PCI_DEVICES));
    VMM_ASSERT(gpci);

    if(gpci == NULL)
    {
        return FALSE;
    }

    gpci->guest_id = guest_id;

    list_add(guest_pci_devices, gpci->guests);

    gpci->gcpu_pci_access_address = (PCI_CONFIG_ADDRESS *) vmm_malloc(guest_gcpu_count(guest_handle(guest_id)) * sizeof(PCI_CONFIG_ADDRESS));
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gpci->gcpu_pci_access_address);

    apply_default_device_assignment(guest_id);
/*
    io_vmexit_handler_register(
                        guest_id,
                        0xCF8,
                        io_pci_address_handler);

    for (port = 0xCFC; port <= 0xCFF; port++)
    {
        io_vmexit_handler_register(
                            guest_id,
                            (IO_PORT_ID) port,
                            io_pci_data_handler);
    }*/

    return TRUE;
}

static void apply_default_device_assignment(GUEST_ID guest_id)
{
    UINT16 bus, dev, func; // 16-bit bus to avoid wrap around on bus==256
    HOST_PCI_DEVICE *host_pci_device = NULL;
    GPCI_GUEST_PROFILE *guest_profile = NULL;
    GUEST_DEVICE_VIRTUALIZATION_TYPE type;

    if(guest_id == guest_get_default_device_owner_guest_id())
    {
        guest_profile = &device_owner_guest_profile;
        type = GUEST_DEVICE_VIRTUALIZATION_DIRECT_ASSIGNMENT;
    }
    else
    {
        guest_profile = &no_devices_guest_profile;
        type = GUEST_DEVICE_VIRTUALIZATION_HIDDEN;
    }
    for(bus = 0; bus < PCI_MAX_NUM_BUSES; bus++)
    {
        for(dev = 0; dev < PCI_MAX_NUM_DEVICES_ON_BUS; dev++)
        {
            for(func = 0; func < PCI_MAX_NUM_FUNCTIONS_ON_DEVICE; func++)
            {
                host_pci_device = get_host_pci_device((UINT8) bus, (UINT8) dev, (UINT8) func);
                if(NULL == host_pci_device)
                {// device not found
                    continue;
                }
                gpci_register_device(guest_id,
                                     type,
                                     host_pci_device,
                                     NULL,
                                     guest_profile->pci_read,
                                     guest_profile->pci_write);
            }
        }
    }

}

BOOLEAN gpci_register_device(GUEST_ID                         guest_id,
                             GUEST_DEVICE_VIRTUALIZATION_TYPE type,
                             HOST_PCI_DEVICE                  *host_pci_device,
                             UINT8*                           config_space,
                             GUEST_PCI_READ_HANDLER           pci_read,
                             GUEST_PCI_WRITE_HANDLER          pci_write)
{
    GUEST_PCI_DEVICE *guest_pci_device = NULL;
    GUEST_PCI_DEVICES *gpci = find_guest_devices(guest_id);
    PCI_DEV_INDEX dev_index = 0;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(NULL != gpci);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(NULL != host_pci_device);

    dev_index = gpci->device_lookup_table[host_pci_device->address];

    if(dev_index != 0)
    {// already registered
        VMM_LOG(mask_anonymous, level_trace,"Warning: guest pci duplicate registration: guest #%d device(%d, %d, %d)\r\n",
            guest_id, GET_PCI_BUS(host_pci_device->address), GET_PCI_DEVICE(host_pci_device->address), GET_PCI_FUNCTION(host_pci_device->address));
        return FALSE;
    }

    dev_index = (PCI_DEV_INDEX) gpci->num_devices++;
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(dev_index < PCI_MAX_NUM_SUPPORTED_DEVICES + 1);
    gpci->device_lookup_table[host_pci_device->address] = dev_index;
    guest_pci_device = &gpci->devices[dev_index];
    vmm_zeromem(guest_pci_device, sizeof(GUEST_PCI_DEVICE));

    guest_pci_device->guest_id = guest_id;
    guest_pci_device->host_device = host_pci_device;
    guest_pci_device->config_space = config_space;
    guest_pci_device->pci_read = pci_read;
    guest_pci_device->pci_write = pci_write;
    guest_pci_device->type = type;

    switch(type)
    {
    case GUEST_DEVICE_VIRTUALIZATION_DIRECT_ASSIGNMENT:
        hash64_insert(device_to_guest, (UINT64) host_pci_device->address, guest_id);
        break;

    case GUEST_DEVICE_VIRTUALIZATION_HIDDEN:
        break;

    default:
        // BEFORE_VMLAUNCH. This case should not happen.
        VMM_ASSERT(0);
        break;
    }

    return TRUE;
}

static GUEST_PCI_DEVICES* find_guest_devices(GUEST_ID guest_id)
{
    GUEST_PCI_DEVICES *guest_devices = NULL;
    LIST_ELEMENT *guest_iter = NULL;
    BOOLEAN guest_found = FALSE;

    LIST_FOR_EACH(guest_pci_devices, guest_iter)
    {
        guest_devices = LIST_ENTRY(guest_iter, GUEST_PCI_DEVICES, guests);
        if(guest_devices->guest_id == guest_id)
        {
            guest_found = TRUE;
            break;
        }
    }
    if(guest_found)
    {
        return guest_devices;
    }
    return NULL;
}

#ifdef INCLUDE_UNUSED_CODE
static GUEST_PCI_DEVICE* find_device(GUEST_ID guest_id, UINT8 bus, UINT8 device, UINT8 function)
{
    GUEST_PCI_DEVICES *gpci;
    PCI_DEV_INDEX dev_index;

    gpci = find_guest_devices(guest_id);
    VMM_ASSERT(gpci);
    dev_index = gpci->device_lookup_table[PCI_GET_ADDRESS(bus, device, function)];
    if(dev_index == 0)
    {
        return NULL;
    }
    return &gpci->devices[dev_index];
}

void gpci_unregister_device(GUEST_ID guest_id, UINT16 bus, UINT16 device, UINT16 function)
{
    GUEST_PCI_DEVICE *guest_pci_device = NULL;
    GUEST_PCI_DEVICES *gpci;
    PCI_DEV_INDEX dev_index;

    gpci = find_guest_devices(guest_id);
    VMM_ASSERT(gpci);

    dev_index = gpci->device_lookup_table[PCI_GET_ADDRESS(bus, device, function)];
    if(dev_index == 0)
    {// not found
        return;
    }

    guest_pci_device = &gpci->devices[dev_index];
    if(guest_pci_device->type == GUEST_DEVICE_VIRTUALIZATION_DIRECT_ASSIGNMENT)
    {
        hash64_remove(device_to_guest, (UINT64) guest_pci_device->host_device->address);
    }
    gpci->device_lookup_table[PCI_GET_ADDRESS(bus, device, function)] = 0;
}
#endif

GUEST_ID gpci_get_device_guest_id(UINT16 bus, UINT16 device, UINT16 function)
{
    BOOLEAN status = FALSE;
    UINT64 owner_guest_id = 0;

    if(FALSE == PCI_IS_ADDRESS_VALID(bus, device, function))
    {
        return INVALID_GUEST_ID;
    }

    status = hash64_lookup(device_to_guest, (UINT64) PCI_GET_ADDRESS(bus, device, function), &owner_guest_id);

    return (GUEST_ID) owner_guest_id;
}

static
void pci_read_hide (GUEST_CPU_HANDLE  gcpu UNUSED,
                    GUEST_PCI_DEVICE *pci_device UNUSED,
                    UINT32 port_id UNUSED,
                    UINT32 port_size,
                    void   *value)
{
    vmm_memset(value, 0xff, port_size);
}

static
void pci_write_hide (GUEST_CPU_HANDLE  gcpu UNUSED,
                     GUEST_PCI_DEVICE *pci_device UNUSED,
                     UINT32 port_id UNUSED,
                     UINT32 port_size UNUSED,
                     void   *value UNUSED)
{
}

static
void pci_read_passthrough (GUEST_CPU_HANDLE  gcpu,
                           GUEST_PCI_DEVICE *pci_device UNUSED,
                           UINT32 port_id,
                           UINT32 port_size,
                           void   *value)
{
    io_transparent_read_handler(gcpu, (IO_PORT_ID) port_id, port_size, value);
}

static
void pci_write_passthrough (GUEST_CPU_HANDLE  gcpu,
                            GUEST_PCI_DEVICE *pci_device UNUSED,
                            UINT32 port_id,
                            UINT32 port_size,
                            void   *value)
{
    io_transparent_write_handler(gcpu, (IO_PORT_ID) port_id, port_size, &value);
}

#ifdef INCLUDE_UNUSED_CODE
static void io_read_pci_address(GUEST_CPU_HANDLE  gcpu,
                                UINT16            port_id UNUSED,
                                unsigned          port_size, // 1, 2, 4
                                void              *p_value)
{
    GUEST_PCI_DEVICES *gpci = NULL;
    const VIRTUAL_CPU_ID *vcpu = NULL;

    vcpu = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu);

    gpci = find_guest_devices(vcpu->guest_id);
    VMM_ASSERT(gpci);

    vmm_memcpy(p_value, (void *) &(gpci->gcpu_pci_access_address[vcpu->guest_cpu_id]), port_size);

}

static void io_write_pci_address(GUEST_CPU_HANDLE  gcpu,
                                 UINT16            port_id UNUSED,
                                 unsigned          port_size, // 1, 2, 4
                                 void              *p_value)
{
    GUEST_PCI_DEVICES *gpci = NULL;
    const VIRTUAL_CPU_ID *vcpu = NULL;

    vcpu = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu);

    gpci = find_guest_devices(vcpu->guest_id);
    VMM_ASSERT(gpci);

    vmm_memcpy((void *) &(gpci->gcpu_pci_access_address[vcpu->guest_cpu_id]), p_value, port_size);
}

static void io_pci_address_handler(GUEST_CPU_HANDLE  gcpu,
                                   UINT16            port_id,
                                   unsigned          port_size, // 1, 2, 4
                                   RW_ACCESS         access,
                                   void              *p_value)
{
    VMM_LOG(mask_anonymous, level_trace,"io_pci_address_handler cpu#%d: port %p size %p rw %p\n", hw_cpu_id(), port_id, port_size, access);
    switch (access)
    {
    case WRITE_ACCESS:
        io_write_pci_address(gcpu, port_id, port_size, p_value);
        break;
    case READ_ACCESS:
        io_read_pci_address(gcpu, port_id, port_size, p_value);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO access(%d)\n", access);
        VMM_DEADLOOP();
        break;
    }
}

static void io_read_pci_data(GUEST_CPU_HANDLE  gcpu,
                             UINT16            port_id,
                             unsigned          port_size, // 1, 2, 4
                             void              *p_value)
{
    GUEST_PCI_DEVICES *gpci = NULL;
    const VIRTUAL_CPU_ID *vcpu = NULL;
    PCI_CONFIG_ADDRESS *pci_addr = NULL;
    GUEST_PCI_DEVICE *guest_pci_device = NULL;

    vcpu = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu);

    gpci = find_guest_devices(vcpu->guest_id);
    VMM_ASSERT(gpci);

    pci_addr = &gpci->gcpu_pci_access_address[vcpu->guest_cpu_id];
    guest_pci_device = find_device(vcpu->guest_id, (UINT8) pci_addr->Bits.Bus, (UINT8) pci_addr->Bits.Device, (UINT8) pci_addr->Bits.Function);

    if(0 == pci_addr->Bits.Enable || guest_pci_device == NULL)
    {
        vmm_memset(p_value, 0xff, port_size);
    }
    else
    {
        guest_pci_device->pci_read(gcpu, guest_pci_device, port_id, port_size, p_value);
    }
}


static void io_write_pci_data(GUEST_CPU_HANDLE  gcpu,
                              UINT16            port_id,
                              unsigned          port_size, // 1, 2, 4
                              void              *p_value)
{
    GUEST_PCI_DEVICES *gpci = NULL;
    const VIRTUAL_CPU_ID *vcpu = NULL;
    PCI_CONFIG_ADDRESS *pci_addr = NULL;
    GUEST_PCI_DEVICE *device = NULL;

    vcpu = guest_vcpu(gcpu);
    VMM_ASSERT(vcpu);

    gpci = find_guest_devices(vcpu->guest_id);
    VMM_ASSERT(gpci);

    pci_addr = &gpci->gcpu_pci_access_address[vcpu->guest_cpu_id];
    device = find_device(vcpu->guest_id, (UINT8) pci_addr->Bits.Bus, (UINT8) pci_addr->Bits.Device, (UINT8) pci_addr->Bits.Function);

    if(1 == pci_addr->Bits.Enable && device != NULL)
    {
        device->pci_write(gcpu, device, port_id, port_size, p_value);
    }
}

static void io_pci_data_handler(GUEST_CPU_HANDLE  gcpu,
                                UINT16            port_id,
                                unsigned          port_size, // 1, 2, 4
                                RW_ACCESS         access,
                                void              *p_value)
{
    VMM_LOG(mask_anonymous, level_trace,"io_pci_data_handler cpu#%d: port %p size %p rw %p\n", hw_cpu_id(), port_id, port_size, access);

    switch (access)
    {
    case WRITE_ACCESS:
        io_write_pci_data(gcpu, port_id, port_size, p_value);
        break;
    case READ_ACCESS:
        io_read_pci_data(gcpu, port_id, port_size, p_value);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO access(%d)\n", access);
        VMM_DEADLOOP();
        break;
    }
}
#endif

#endif //PCI_SCAN

