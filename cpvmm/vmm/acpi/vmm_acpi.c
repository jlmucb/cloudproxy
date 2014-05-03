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

#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "libc.h"
#include "host_memory_manager_api.h"
#include "file_codes.h"
#include "vmm_acpi.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_ACPI_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_ACPI_C, __condition)
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


#ifdef USE_ACPI

static ACPI_TABLE_FADT fadt; // locally stored FADT
static char sleep_conversion_table[ACPI_PM1_CNTRL_REG_COUNT][ACPI_S_STATE_COUNT] = { 0 };

#pragma warning (push)
#pragma warning (disable : 4100)
void vmm_acpi_print_header(ACPI_TABLE_HEADER *pTableHeader)
{
    VMM_LOG(mask_anonymous, level_trace,"==============Header===============\n");
    VMM_LOG(mask_anonymous, level_trace,"Signature     = %c%c%c%c\n",
        pTableHeader->Signature[0], pTableHeader->Signature[1],
        pTableHeader->Signature[2], pTableHeader->Signature[3]);
    VMM_LOG(mask_anonymous, level_trace,"Length        = 0x%x\n", pTableHeader->Length);
    VMM_LOG(mask_anonymous, level_trace,"Revision      = %d\n", pTableHeader->Revision);
    VMM_LOG(mask_anonymous, level_trace,"Checksum      = 0x%x\n", pTableHeader->Checksum);
    VMM_LOG(mask_anonymous, level_trace,"OemId         = %c%c%c%c%c%c\n",
        pTableHeader->OemId[0], pTableHeader->OemId[1],
        pTableHeader->OemId[2], pTableHeader->OemId[3],
        pTableHeader->OemId[4], pTableHeader->OemId[5]);
    VMM_LOG(mask_anonymous, level_trace,"OemTableId    = %c%c%c%c%c%c%c%c\n",
        pTableHeader->OemTableId[0], pTableHeader->OemTableId[1],
        pTableHeader->OemTableId[2], pTableHeader->OemTableId[3],
        pTableHeader->OemTableId[4], pTableHeader->OemTableId[5],
        pTableHeader->OemTableId[6], pTableHeader->OemTableId[7]);
    VMM_LOG(mask_anonymous, level_trace,"OemRevision   = %d\n", pTableHeader->OemRevision);
    VMM_LOG(mask_anonymous, level_trace,"AslCompilerId = %c%c%c%c\n",
        pTableHeader->AslCompilerId[0], pTableHeader->AslCompilerId[1],
        pTableHeader->AslCompilerId[2], pTableHeader->AslCompilerId[3]);
    VMM_LOG(mask_anonymous, level_trace,"AslCompilerRevision= %d\n", pTableHeader->AslCompilerRevision);
    VMM_LOG(mask_anonymous, level_trace,"-----------------------------------\n");
}

void vmm_acpi_print_fadt(ACPI_TABLE_FADT *fadt)
{
    VMM_LOG(mask_anonymous, level_trace,"===============FADT================\n");
    vmm_acpi_print_header(&fadt->Header);
    VMM_LOG(mask_anonymous, level_trace,"Facs              : %p\n", fadt->Facs);
    VMM_LOG(mask_anonymous, level_trace,"Dsdt              : %p\n", fadt->Dsdt);
    VMM_LOG(mask_anonymous, level_trace,"Model             : %d\n", fadt->Model);
    VMM_LOG(mask_anonymous, level_trace,"PreferredProfile  : %d\n", fadt->PreferredProfile);
    VMM_LOG(mask_anonymous, level_trace,"SciInterrupt      : 0x%x\n", fadt->SciInterrupt);
    VMM_LOG(mask_anonymous, level_trace,"SmiCommand        : 0x%x\n", fadt->SmiCommand);
    VMM_LOG(mask_anonymous, level_trace,"AcpiEnable        : 0x%x\n", fadt->AcpiEnable);
    VMM_LOG(mask_anonymous, level_trace,"AcpiDisable       : 0x%x\n", fadt->AcpiDisable);
    VMM_LOG(mask_anonymous, level_trace,"S4BiosRequest     : 0x%x\n", fadt->S4BiosRequest);
    VMM_LOG(mask_anonymous, level_trace,"PstateControl     : 0x%x\n", fadt->PstateControl);
    VMM_LOG(mask_anonymous, level_trace,"Pm1aEventBlock    : 0x%x\n", fadt->Pm1aEventBlock);
    VMM_LOG(mask_anonymous, level_trace,"Pm1aEventBlock    : 0x%x\n", fadt->Pm1aEventBlock);
    VMM_LOG(mask_anonymous, level_trace,"Pm1bEventBlock    : 0x%x\n", fadt->Pm1bEventBlock);
    VMM_LOG(mask_anonymous, level_trace,"Pm1aControlBlock  : 0x%x\n", fadt->Pm1aControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"Pm1bControlBlock  : 0x%x\n", fadt->Pm1bControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"Pm2ControlBlock   : 0x%x\n", fadt->Pm2ControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"PmTimerBlock      : 0x%x\n", fadt->PmTimerBlock);
    VMM_LOG(mask_anonymous, level_trace,"Gpe0Block         : 0x%x\n", fadt->Gpe0Block);
    VMM_LOG(mask_anonymous, level_trace,"Gpe1Block         : 0x%x\n", fadt->Gpe1Block);
    VMM_LOG(mask_anonymous, level_trace,"Pm1EventLength    : 0x%x\n", fadt->Pm1EventLength);
    VMM_LOG(mask_anonymous, level_trace,"Pm1ControlLength  : 0x%x\n", fadt->Pm1ControlLength);
    VMM_LOG(mask_anonymous, level_trace,"Pm2ControlLength  : 0x%x\n", fadt->Pm2ControlLength);
    VMM_LOG(mask_anonymous, level_trace,"PmTimerLength     : 0x%x\n", fadt->PmTimerLength);
    VMM_LOG(mask_anonymous, level_trace,"Gpe0BlockLength   : 0x%x\n", fadt->Gpe0BlockLength);
    VMM_LOG(mask_anonymous, level_trace,"Gpe1BlockLength   : 0x%x\n", fadt->Gpe1BlockLength);
    VMM_LOG(mask_anonymous, level_trace,"Gpe1Base          : 0x%x\n", fadt->Gpe1Base);
    VMM_LOG(mask_anonymous, level_trace,"CstControl        : 0x%x\n", fadt->CstControl);
    VMM_LOG(mask_anonymous, level_trace,"C2Latency         : 0x%x\n", fadt->C2Latency);
    VMM_LOG(mask_anonymous, level_trace,"C3Latency         : 0x%x\n", fadt->C3Latency);
    VMM_LOG(mask_anonymous, level_trace,"FlushSize         : 0x%x\n", fadt->FlushSize);
    VMM_LOG(mask_anonymous, level_trace,"FlushStride       : 0x%x\n", fadt->FlushStride);
    VMM_LOG(mask_anonymous, level_trace,"DutyOffset        : 0x%x\n", fadt->DutyOffset);
    VMM_LOG(mask_anonymous, level_trace,"DutyWidth         : 0x%x\n", fadt->DutyWidth);
    VMM_LOG(mask_anonymous, level_trace,"DayAlarm          : 0x%x\n", fadt->DayAlarm);
    VMM_LOG(mask_anonymous, level_trace,"MonthAlarm        : 0x%x\n", fadt->MonthAlarm);
    VMM_LOG(mask_anonymous, level_trace,"Century           : 0x%x\n", fadt->Century);
    VMM_LOG(mask_anonymous, level_trace,"BootFlags         : 0x%x\n", fadt->BootFlags);
    VMM_LOG(mask_anonymous, level_trace,"Flags             : 0x%x\n", fadt->Flags);
    VMM_LOG(mask_anonymous, level_trace,"ResetRegister     : 0x%x\n", fadt->ResetRegister);
    VMM_LOG(mask_anonymous, level_trace,"ResetValue        : 0x%x\n", fadt->ResetValue);
    VMM_LOG(mask_anonymous, level_trace,"XFacs             : 0x%x\n", fadt->XFacs);
    VMM_LOG(mask_anonymous, level_trace,"XDsdt             : 0x%x\n", fadt->XDsdt);
    VMM_LOG(mask_anonymous, level_trace,"XPm1aEventBlock   : 0x%x\n", fadt->XPm1aEventBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPm1bEventBlock   : 0x%x\n", fadt->XPm1bEventBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPm1aControlBlock : 0x%x\n", fadt->XPm1aControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPm1bControlBlock : 0x%x\n", fadt->XPm1bControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPm2ControlBlock  : 0x%x\n", fadt->XPm2ControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPm2ControlBlock  : 0x%x\n", fadt->XPm2ControlBlock);
    VMM_LOG(mask_anonymous, level_trace,"XPmTimerBlock     : 0x%x\n", fadt->XPmTimerBlock);
    VMM_LOG(mask_anonymous, level_trace,"XGpe0Block        : 0x%x\n", fadt->XGpe0Block);
    VMM_LOG(mask_anonymous, level_trace,"XGpe1Block        : 0x%x\n", fadt->XGpe1Block);
    VMM_LOG(mask_anonymous, level_trace,"===================================\n");
}


void vmm_acpi_print_facs(ACPI_TABLE_FACS *facs)
{
    VMM_LOG(mask_anonymous, level_trace,"===============FACS================\n");
    VMM_LOG(mask_anonymous, level_trace,"Signature         : %c%c%c%c\n",
        facs->Signature[0],
        facs->Signature[1],
        facs->Signature[2],
        facs->Signature[3]);
    VMM_LOG(mask_anonymous, level_trace,"Length                : %d\n", facs->Length);
    VMM_LOG(mask_anonymous, level_trace,"HardwareSignature     : 0x%x\n", facs->HardwareSignature);
    VMM_LOG(mask_anonymous, level_trace,"FirmwareWakingVector  : 0x%x\n", facs->FirmwareWakingVector);
    VMM_LOG(mask_anonymous, level_trace,"Flags                 : 0x%x\n", facs->Flags);
    VMM_LOG(mask_anonymous, level_trace,"XFirmwareWakingVector : 0x%x\n", facs->XFirmwareWakingVector);
    VMM_LOG(mask_anonymous, level_trace,"Version               : %d\n", facs->Version);
}
#pragma warning (pop)

INLINE VOID *acpi_map_memory(UINT64 where)
{
    HVA hva;
    hmm_hpa_to_hva((HPA) where, &hva);
    return (void*) hva;
}

/* Calculate acpi table checksum */
INLINE UINT8 checksum(UINT8 * buffer, UINT32 length)
{
    int sum = 0;
    UINT8 *i = buffer;
    buffer += length;
    for (; i < buffer; sum += *(i++)) ;
    return (char) sum;
}

/* Scan for RSDP table and return mapped address of rsdp, if found */
INLINE ACPI_TABLE_RSDP *scan_for_rsdp(void *addr, UINT32 length)
{
    ACPI_TABLE_RSDP *rsdp, *result = NULL;
    unsigned char *begin;
    unsigned char *i, *end;

    begin = addr;
    end = begin + length;

    /* Search from given start address for the requested length */
    for (i = begin; i < end; i += ACPI_RSDP_SCAN_STEP) {
        /* The signature and checksum must both be correct */
        if (vmm_memcmp((char *)i, "RSD PTR ", 8)) {
            continue;
        }

        VMM_LOG(mask_anonymous, level_trace,"Got the rsdp header, now check the checksum\n");
        rsdp = (ACPI_TABLE_RSDP *)i;

        /* Signature matches, check the appropriate checksum */
        if (!checksum((unsigned char *)rsdp, (rsdp->Revision < 2) ?
                      ACPI_RSDP_CHECKSUM_LENGTH :
                      ACPI_RSDP_XCHECKSUM_LENGTH)) {
            /* Checksum valid, we have found a valid RSDP */
            VMM_LOG(mask_anonymous, level_trace,"Found acpi rsdp table\n");
            result = rsdp;
            break;
        }
    }
    return(result);
}


/* Find an acpi table with specified signature and return mapped address */
INLINE ACPI_TABLE_HEADER * get_acpi_table_from_rsdp(ACPI_TABLE_RSDP *rsdp, char *sig)
{
    ACPI_TABLE_HEADER *sdt = NULL;
    ACPI_TABLE_HEADER *tbl = NULL;
    int xsdt = 1;
    int i;
    int num;
    char *offset;

    /* Get xsdt pointer */
    if (rsdp->Revision > 1 && rsdp->XsdtPhysicalAddress) {
        VMM_LOG(mask_anonymous, level_trace,"rsdp->xsdt_physical_address %lx\n", 
                rsdp->XsdtPhysicalAddress);
                sdt = acpi_map_memory(rsdp->XsdtPhysicalAddress);
    }

    /* Or get rsdt */
    if (!sdt && rsdp->RsdtPhysicalAddress) {
        xsdt = 0;
        VMM_LOG(mask_anonymous, level_trace,"rsdp->rsdt_physical_address  = %x\n", 
                rsdp->RsdtPhysicalAddress);
                sdt = acpi_map_memory(rsdp->RsdtPhysicalAddress);
    }

    /* Check if the rsdt/xsdt table pointer is NULL */
    if (NULL == sdt) {
        VMM_LOG(mask_anonymous, level_error,"Map rsdt/xsdt error\n");
        return NULL;
    }

    /* Make sure the table checksum is correct */
    if (checksum((unsigned char *)sdt, sdt->Length)) {
        VMM_LOG(mask_anonymous, level_error,"Wrong checksum in %s!\n", (xsdt)?"XSDT":"RSDT");
        return NULL;
    }

    VMM_LOG(mask_anonymous, level_trace,"xsdt/rsdt checksum verified!\n");

    /* Calculate the number of table pointers in the xsdt or rsdt table */
    num = (sdt->Length - sizeof(ACPI_TABLE_HEADER))/
          ((xsdt) ? sizeof(UINT64) : sizeof(UINT32));

    VMM_LOG(mask_anonymous, level_trace,"The number of table pointers in xsdt/rsdt = %d\n", 
               num);

    /* Get to the table pointer area */
    offset = (char *)sdt + sizeof(ACPI_TABLE_HEADER);

    /* Traverse the pointer list to get the desired acpi table */
    for (i = 0; i < num; ++i, offset += ((xsdt) ? sizeof(UINT64) : sizeof(UINT32))) {
        /* Get the address from the pointer entry */
        tbl= acpi_map_memory((UINT64) ((xsdt) ? (*(UINT64 *)offset):(*(UINT32 *)offset)));

        /* Make sure address is valid */
        if (!tbl) {
            continue;
        }

        VMM_LOG(mask_anonymous, level_trace,"Mapped ACPI table addr = %p, ", tbl);
        VMM_LOG(mask_anonymous, level_trace,"Signature = %c%c%c%c\n", 
                tbl->Signature[0], 
                tbl->Signature[1],
                tbl->Signature[2],
                tbl->Signature[3]);

        /* Verify table signature & table checksum */
        if ((0 == vmm_memcmp(tbl->Signature, sig, 4)) &&
            !checksum((unsigned char *)tbl, tbl->Length)) {
            /* Found the table with matched signature */
            VMM_LOG(mask_anonymous, level_trace,"Found the table %s address = %p length = %x\n", sig, tbl, tbl->Length);

            return tbl;
        }
    }
    VMM_LOG(mask_anonymous, level_error,"Could not find %s table in XSDT/RSDT\n", sig);
    return NULL;
}

ACPI_TABLE_HEADER * vmm_acpi_locate_table(char *sig)
{
    ACPI_TABLE_RSDP *rsdp = NULL;
    void *table = NULL;
        
    /* Try 0x0 first for getting rsdp table */
    rsdp = scan_for_rsdp(acpi_map_memory(0), 0x400);
    if (NULL == rsdp) {
        /* Try 0xE0000 */
        VMM_LOG(mask_anonymous, level_trace,"Try 0xE0000 for ACPI RSDP table\n");
        rsdp = scan_for_rsdp(acpi_map_memory(0xE0000), 0x1FFFF);
    }

    if (NULL == rsdp) {
        VMM_LOG(mask_anonymous, level_error,"Could not find the rsdp table\n");
        return NULL;
    }

    VMM_LOG(mask_anonymous, level_trace,"rsdp address %p\n", rsdp);

    /* Get the specified table from rsdp */
    table = get_acpi_table_from_rsdp(rsdp, sig);
    return table;
}


// SLP_TYP values are programmed in PM1A and PM1B control block registers
// to initiate power transition.  Each Sx state has a corresponding SLP_TYP value.
// SLP_TYP values are stored in DSDT area of ACPI tables as AML packages
// Following code searches for these packages to retreive the SLP_TYPs
//
// Search for '_SX_' to get to start of package.  'X' stands for sleep state e.g. '_S3_'
// If '_SX_' is not found then it means the system does not support that sleep state.
// _SX_packages are in the following format 
// 1 byte                   :   Package Op (0x12)
// 1 byte                   
// + 'Package Length' size  :   'Package Length' field.  Refer ACPI spec for 
//                              'Package Length Encoding' High 2 bits of first byte 
//                              indicates how many bytes are used by 'Package Length'
//                              If 0, then only the first byte is used
//                              If > 0 then following bytes (max 3) will be also used
// 
// 1 byte                   :   'Number of Elements'
//
// 1 byte optional          :   There may be an optional 'Byte Prefix' (0x0A) present.
//
// 1 byte SLP_TYP_A         :   SLP_TYP value for PM1A control block
//
// 1 byte optional          :   There may be an optional 'Byte Prefix' (0x0A) present.
// 
// 1 byte SLP_TYP_B         :   SLP_TYP value for PM1B control block
//
// Remaining bytes are ignored. 
//
void vmm_acpi_retrieve_sleep_states(void)
{
    ACPI_TABLE_HEADER *dsdt;
        char *aml_ptr;
    UINT8 sstate;
    UINT32 i;

    dsdt =  acpi_map_memory((UINT64) fadt.Dsdt);
    if (!dsdt) {
        VMM_LOG(mask_anonymous, level_error,"[ACPI] DSDT not found\n");
        return;
    }

    VMM_LOG(mask_anonymous, level_trace,"SleepState | SleepTypeA | SleepTypeB\n");
    VMM_LOG(mask_anonymous, level_trace,"------------------------------------\n");
        
    for (sstate = ACPI_STATE_S0; sstate < ACPI_S_STATE_COUNT; ++sstate) {
        aml_ptr = (char *) (dsdt + sizeof(ACPI_TABLE_HEADER));  
                
        sleep_conversion_table[ACPI_PM1_CNTRL_REG_A][sstate] = 0xff;
        sleep_conversion_table[ACPI_PM1_CNTRL_REG_B][sstate] = 0xff;
                
        //Search  for '_SX_' string where 'X' is the sleep state e.g. '_S3_' 
        for (i = 0; i < dsdt->Length - 8; i++) {
            if (aml_ptr[0] == '_' && aml_ptr[1] == 'S' && aml_ptr[2] == ('0' + sstate) && aml_ptr[3] == '_')
                break;
            aml_ptr++;
        }
        if (i < dsdt->Length - 8) {
            //Skip '_SX_' and Package Op
            aml_ptr += 5;

            //Skip 'Package Length' bytes indicated by the 2 high bits of 'Package Lead' byte
            aml_ptr += (*aml_ptr >> 6);

            //Skip 'Package Lead' byte
            aml_ptr++;

            //Skip 'Number of Elements' byte
            aml_ptr++;

            //Skip 'Byte Prefix' if found
            if (*aml_ptr == 0x0a)
                aml_ptr++;
                        
            //This should be SLP_TYP value for PM1A_CNT_BLK
            sleep_conversion_table[ACPI_PM1_CNTRL_REG_A][sstate] = *aml_ptr;
            aml_ptr++;

            //Skip 'Byte Prefix' if found
            if (*aml_ptr == 0x0a)
                aml_ptr++;
                        
            //This should be SLP_TYP value for PM1B_CNT_BLK
            sleep_conversion_table[ACPI_PM1_CNTRL_REG_B][sstate] = *aml_ptr;
        }
                
        VMM_LOG(mask_anonymous, level_trace,"    %3d    |    %3d     |    %3d\n",
                    sstate,
                    sleep_conversion_table[ACPI_PM1_CNTRL_REG_A][sstate],
                    sleep_conversion_table[ACPI_PM1_CNTRL_REG_B][sstate]);
        }
}

int vmm_acpi_init(HVA fadt_hva)
{
    ACPI_TABLE_HEADER *pTable;

    pTable = (ACPI_TABLE_HEADER *)fadt_hva;

    if (NULL != pTable) {
        //Keep a local copy of fadt to avoid losing the tables if OS reuses acpi memory
        fadt = *(ACPI_TABLE_FADT *) pTable;
        vmm_acpi_print_fadt((ACPI_TABLE_FADT *) pTable);
    }
#ifdef ENABLE_PM_S3
    // Get Sleep Data
    vmm_acpi_retrieve_sleep_states();
#endif
    return 1;
}

UINT16 vmm_acpi_smi_cmd_port(void)
{
    return (UINT16) fadt.SmiCommand;
}

UINT8 vmm_acpi_pm_port_size(void)
{
    return fadt.Pm1ControlLength;
}

UINT32 vmm_acpi_pm_port_a(void)
{
    return fadt.Pm1aControlBlock;
}

UINT32 vmm_acpi_pm_port_b(void)
{
    return fadt.Pm1bControlBlock;
}

unsigned vmm_acpi_sleep_type_to_state(unsigned pm_reg_id, unsigned sleep_type)
{
    int sstate;

    if (pm_reg_id >= ACPI_PM1_CNTRL_REG_COUNT) {
        VMM_LOG(mask_anonymous, level_error,"[ACPI] got bad input. pm_reg_id(%d) sleep_type(%d)\n",
            pm_reg_id, sleep_type);
        return 0;
    }
    for (sstate = ACPI_STATE_S0; sstate < ACPI_S_STATE_COUNT; ++sstate) {
        if (sleep_conversion_table[pm_reg_id][sstate] == (char) sleep_type) {
            return sstate;  // found
        }
    }
    VMM_LOG(mask_anonymous, level_error,"[ACPI] got bad input. pm_reg_id(%d) sleep_type(%d)\n",
            pm_reg_id, sleep_type);
    return 0;   // sleep_type not recognized
}

int vmm_acpi_waking_vector(UINT32 *p_waking_vector, UINT64 *p_extended_waking_vector)
{
    ACPI_TABLE_FACS *p_facs;

    p_facs = (ACPI_TABLE_FACS *) (size_t) fadt.Facs;
    if (NULL == p_facs) {
        p_facs = (ACPI_TABLE_FACS *) fadt.XFacs;
    }
    if (NULL == p_facs) {
        VMM_LOG(mask_anonymous, level_error,"[acpi] FACS is not detected. S3 is not supported by the platform\n");
        return -1;  // error
    }
    VMM_LOG(mask_anonymous, level_trace,"[acpi] FirmwareWakingVector=%P  XFirmwareWakingVector=%P\n",
        p_facs->FirmwareWakingVector, p_facs->XFirmwareWakingVector);
    *p_waking_vector          = p_facs->FirmwareWakingVector;
    *p_extended_waking_vector = p_facs->XFirmwareWakingVector;
    return 0;   // OK
}
#else
UINT16 vmm_acpi_smi_cmd_port(void)
{
    //return (UINT16) fadt.SmiCommand;
    
    //ACPI is gone, we can only support late launch.
    // it should never come here. Let's put a 
    // deadloop. The whole function is just to make
    //compiler happy.
    VMM_DEADLOOP();
    return 0;
}

#endif //USE_ACPI

