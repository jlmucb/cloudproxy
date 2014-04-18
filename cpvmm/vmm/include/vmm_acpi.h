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

#ifndef _VMM_ACPI_H_
#define _VMM_ACPI_H_

#define ACPI_PM1_CNTRL_REG_A        0
#define ACPI_PM1_CNTRL_REG_B        1
#define ACPI_PM1_CNTRL_REG_COUNT    2

#define ACPI_NAME_SIZE                  4
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8

#define ACPI_STATE_UNKNOWN              (UINT8) 0xFF

#define ACPI_STATE_S0                   (UINT8) 0
#define ACPI_STATE_S1                   (UINT8) 1
#define ACPI_STATE_S2                   (UINT8) 2
#define ACPI_STATE_S3                   (UINT8) 3
#define ACPI_STATE_S4                   (UINT8) 4
#define ACPI_STATE_S5                   (UINT8) 5
#define ACPI_S_STATES_MAX               ACPI_STATE_S5
#define ACPI_S_STATE_COUNT              6

/*
 * Values for description table header signatures. Useful because they make
 * it more difficult to inadvertently type in the wrong signature.
 */
#define ACPI_SIG_DSDT           "DSDT"      /* Differentiated System Description Table */
#define ACPI_SIG_FADT           "FACP"      /* Fixed ACPI Description Table */
#define ACPI_SIG_FACS           "FACS"      /* Firmware ACPI Control Structure */
#define ACPI_SIG_PSDT           "PSDT"      /* Persistent System Description Table */
#define ACPI_SIG_RSDP           "RSD PTR "  /* Root System Description Pointer */
#define ACPI_SIG_RSDT           "RSDT"      /* Root System Description Table */
#define ACPI_SIG_XSDT           "XSDT"      /* Extended  System Description Table */
#define ACPI_SIG_SSDT           "SSDT"      /* Secondary System Description Table */
#define ACPI_RSDP_NAME          "RSDP"      /* Short name for RSDP, not signature */
#define ACPI_SIG_DMAR           "DMAR"      /* DMA Remapping table */

/* RSDP scan step */
#define ACPI_RSDP_SCAN_STEP 16

/* RSDP checksums */

#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_XCHECKSUM_LENGTH      36

/*
 * All tables and structures must be byte-packed to match the ACPI
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)


/*
 * These are the ACPI tables that are directly consumed by the subsystem.
 *
 * The RSDP and FACS do not use the common ACPI table header. All other ACPI
 * tables use the header.
 *
 * Note about bitfields: The UINT8 type is used for bitfields in ACPI tables.
 * This is the only type that is even remotely portable. Anything else is not
 * portable, so do not use any other bitfield types.
 */

/*
 *
 * ACPI Table Header. This common header is used by all tables except the
 * RSDP and FACS. The define is used for direct inclusion of header into
 * other ACPI tables
 *
 */

typedef struct acpi_table_header
{
    char      Signature[ACPI_NAME_SIZE];          /* ASCII table signature */
    UINT32    Length;        /* Length of table in bytes, including this header */
    UINT8     Revision;      /* ACPI Specification minor version # */
    UINT8     Checksum;      /* To make sum of entire table == 0 */
    char      OemId[ACPI_OEM_ID_SIZE];            /* ASCII OEM identification */
    char      OemTableId[ACPI_OEM_TABLE_ID_SIZE]; /* ASCII OEM table identification */
    UINT32    OemRevision;                        /* OEM revision number */
    char      AslCompilerId[ACPI_NAME_SIZE];      /* ASCII ASL compiler vendor ID */
    UINT32    AslCompilerRevision;                /* ASL compiler version */

} ACPI_TABLE_HEADER;


/*
 * GAS - Generic Address Structure (ACPI 2.0+)
 *
 * Note: Since this structure is used in the ACPI tables, it is byte aligned.
 * If misalignment is not supported, access to the Address field must be
 * performed with care.
 */
typedef struct acpi_generic_address
{
    UINT8   SpaceId;                /* Address space where struct or register exists */
    UINT8   BitWidth;               /* Size in bits of given register */
    UINT8   BitOffset;              /* Bit offset within the register */
    UINT8   AccessWidth;            /* Minimum Access size (ACPI 3.0) */
    UINT64  Address;                /* 64-bit address of struct or register */
} ACPI_GENERIC_ADDRESS;


/*
 * RSDP - Root System Description Pointer (Signature is "RSD PTR ")
 */
 

typedef struct acpi_table_rsdp
{
    char   Signature[8];               /* ACPI signature, contains "RSD PTR " */
    UINT8  Checksum;                   /* ACPI 1.0 checksum */
    char   OemId[ACPI_OEM_ID_SIZE];    /* OEM identification */
    UINT8  Revision;    /* Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+ */
    UINT32 RsdtPhysicalAddress;        /* 32-bit physical address of the RSDT */
    UINT32 Length;      /* Table length in bytes, including header (ACPI 2.0+) */
    UINT64 XsdtPhysicalAddress;   /* 64-bit physical address of the XSDT (ACPI 2.0+) */
    UINT8  ExtendedChecksum;           /* Checksum of entire table (ACPI 2.0+) */
    UINT8  Reserved[3];                /* Reserved, must be zero */

} ACPI_TABLE_RSDP;

/*
 * FACS - Firmware ACPI Control Structure (FACS)
 */

typedef struct acpi_table_facs
{
    char     Signature[4];           /* ASCII table signature */
    UINT32   Length;                 /* Length of structure, in bytes */
    UINT32   HardwareSignature;      /* Hardware configuration signature */
    UINT32   FirmwareWakingVector;   /* 32-bit physical address of the Firmware Waking Vector */
    UINT32   GlobalLock;             /* Global Lock for shared hardware resources */
    UINT32   Flags;
    UINT64   XFirmwareWakingVector;  /* 64-bit version of the Firmware Waking Vector (ACPI 2.0+) */
    UINT8    Version;                /* Version of this table (ACPI 2.0+) */
    UINT8    Reserved[31];           /* Reserved, must be zero */
} ACPI_TABLE_FACS;


/*
 * FADT - Fixed ACPI Description Table (Signature "FACP")
 */

/* Fields common to all versions of the FADT */

typedef struct acpi_table_fadt
{
    ACPI_TABLE_HEADER       Header;             /* Common ACPI table header */
    UINT32                  Facs;               /* 32-bit physical address of FACS */
    UINT32                  Dsdt;               /* 32-bit physical address of DSDT */
    UINT8                   Model;              /* System Interrupt Model (ACPI 1.0) - not used in ACPI 2.0+ */
    UINT8                   PreferredProfile;   /* Conveys preferred power management profile to OSPM. */
    UINT16                  SciInterrupt;       /* System vector of SCI interrupt */
    UINT32                  SmiCommand;         /* 32-bit Port address of SMI command port */
    UINT8                   AcpiEnable;         /* Value to write to smi_cmd to enable ACPI */
    UINT8                   AcpiDisable;        /* Value to write to smi_cmd to disable ACPI */
    UINT8                   S4BiosRequest;      /* Value to write to SMI CMD to enter S4BIOS state */
    UINT8                   PstateControl;      /* Processor performance state control*/
    UINT32                  Pm1aEventBlock;     /* 32-bit Port address of Power Mgt 1a Event Reg Blk */
    UINT32                  Pm1bEventBlock;     /* 32-bit Port address of Power Mgt 1b Event Reg Blk */
    UINT32                  Pm1aControlBlock;   /* 32-bit Port address of Power Mgt 1a Control Reg Blk */
    UINT32                  Pm1bControlBlock;   /* 32-bit Port address of Power Mgt 1b Control Reg Blk */
    UINT32                  Pm2ControlBlock;    /* 32-bit Port address of Power Mgt 2 Control Reg Blk */
    UINT32                  PmTimerBlock;       /* 32-bit Port address of Power Mgt Timer Ctrl Reg Blk */
    UINT32                  Gpe0Block;          /* 32-bit Port address of General Purpose Event 0 Reg Blk */
    UINT32                  Gpe1Block;          /* 32-bit Port address of General Purpose Event 1 Reg Blk */
    UINT8                   Pm1EventLength;     /* Byte Length of ports at Pm1xEventBlock */
    UINT8                   Pm1ControlLength;   /* Byte Length of ports at Pm1xControlBlock */
    UINT8                   Pm2ControlLength;   /* Byte Length of ports at Pm2ControlBlock */
    UINT8                   PmTimerLength;      /* Byte Length of ports at PmTimerBlock */
    UINT8                   Gpe0BlockLength;    /* Byte Length of ports at Gpe0Block */
    UINT8                   Gpe1BlockLength;    /* Byte Length of ports at Gpe1Block */
    UINT8                   Gpe1Base;           /* Offset in GPE number space where GPE1 events start */
    UINT8                   CstControl;         /* Support for the _CST object and C States change notification */
    UINT16                  C2Latency;          /* Worst case HW latency to enter/exit C2 state */
    UINT16                  C3Latency;          /* Worst case HW latency to enter/exit C3 state */
    UINT16                  FlushSize;          /* Processor's memory cache line width, in bytes */
    UINT16                  FlushStride;        /* Number of flush strides that need to be read */
    UINT8                   DutyOffset;         /* Processor duty cycle index in processor's P_CNT reg*/
    UINT8                   DutyWidth;          /* Processor duty cycle value bit width in P_CNT register.*/
    UINT8                   DayAlarm;           /* Index to day-of-month alarm in RTC CMOS RAM */
    UINT8                   MonthAlarm;         /* Index to month-of-year alarm in RTC CMOS RAM */
    UINT8                   Century;            /* Index to century in RTC CMOS RAM */
    UINT16                  BootFlags;          /* IA-PC Boot Architecture Flags. See Table 5-10 for description */
    UINT8                   Reserved;           /* Reserved, must be zero */
    UINT32                  Flags;              /* Miscellaneous flag bits (see below for individual flags) */
    ACPI_GENERIC_ADDRESS    ResetRegister;      /* 64-bit address of the Reset register */
    UINT8                   ResetValue;         /* Value to write to the ResetRegister port to reset the system */
    UINT8                   Reserved4[3];       /* Reserved, must be zero */
    UINT64                  XFacs;              /* 64-bit physical address of FACS */
    UINT64                  XDsdt;              /* 64-bit physical address of DSDT */
    ACPI_GENERIC_ADDRESS    XPm1aEventBlock;    /* 64-bit Extended Power Mgt 1a Event Reg Blk address */
    ACPI_GENERIC_ADDRESS    XPm1bEventBlock;    /* 64-bit Extended Power Mgt 1b Event Reg Blk address */
    ACPI_GENERIC_ADDRESS    XPm1aControlBlock;  /* 64-bit Extended Power Mgt 1a Control Reg Blk address */
    ACPI_GENERIC_ADDRESS    XPm1bControlBlock;  /* 64-bit Extended Power Mgt 1b Control Reg Blk address */
    ACPI_GENERIC_ADDRESS    XPm2ControlBlock;   /* 64-bit Extended Power Mgt 2 Control Reg Blk address */
    ACPI_GENERIC_ADDRESS    XPmTimerBlock;      /* 64-bit Extended Power Mgt Timer Ctrl Reg Blk address */
    ACPI_GENERIC_ADDRESS    XGpe0Block;         /* 64-bit Extended General Purpose Event 0 Reg Blk address */
    ACPI_GENERIC_ADDRESS    XGpe1Block;         /* 64-bit Extended General Purpose Event 1 Reg Blk address */

} ACPI_TABLE_FADT;


/* FADT flags */

#define ACPI_FADT_WBINVD            (1)         /* 00: The wbinvd instruction works properly */
#define ACPI_FADT_WBINVD_FLUSH      (1<<1)      /* 01: The wbinvd flushes but does not invalidate */
#define ACPI_FADT_C1_SUPPORTED      (1<<2)      /* 02: All processors support C1 state */
#define ACPI_FADT_C2_MP_SUPPORTED   (1<<3)      /* 03: C2 state works on MP system */
#define ACPI_FADT_POWER_BUTTON      (1<<4)      /* 04: Power button is handled as a generic feature */
#define ACPI_FADT_SLEEP_BUTTON      (1<<5)      /* 05: Sleep button is handled as a generic feature, or  not present */
#define ACPI_FADT_FIXED_RTC         (1<<6)      /* 06: RTC wakeup stat not in fixed register space */
#define ACPI_FADT_S4_RTC_WAKE       (1<<7)      /* 07: RTC wakeup stat not possible from S4 */
#define ACPI_FADT_32BIT_TIMER       (1<<8)      /* 08: tmr_val is 32 bits 0=24-bits */
#define ACPI_FADT_DOCKING_SUPPORTED (1<<9)      /* 09: Docking supported */
#define ACPI_FADT_RESET_REGISTER    (1<<10)     /* 10: System reset via the FADT RESET_REG supported */
#define ACPI_FADT_SEALED_CASE       (1<<11)     /* 11: No internal expansion capabilities and case is sealed */
#define ACPI_FADT_HEADLESS          (1<<12)     /* 12: No local video capabilities or local input devices */
#define ACPI_FADT_SLEEP_TYPE        (1<<13)     /* 13: Must execute native instruction after writing  SLP_TYPx register */
#define ACPI_FADT_PCI_EXPRESS_WAKE  (1<<14)     /* 14: System supports PCIEXP_WAKE (STS/EN) bits (ACPI 3.0) */
#define ACPI_FADT_PLATFORM_CLOCK    (1<<15)     /* 15: OSPM should use platform-provided timer (ACPI 3.0) */
#define ACPI_FADT_S4_RTC_VALID      (1<<16)     /* 16: Contents of RTC_STS valid after S4 wake (ACPI 3.0) */
#define ACPI_FADT_REMOTE_POWER_ON   (1<<17)     /* 17: System is compatible with remote power on (ACPI 3.0) */
#define ACPI_FADT_APIC_CLUSTER      (1<<18)     /* 18: All local APICs must use cluster model (ACPI 3.0) */
#define ACPI_FADT_APIC_PHYSICAL     (1<<19)     /* 19: All local xAPICs must use physical dest mode (ACPI 3.0) */


/* Reset to default packing */

#pragma pack()

int     vmm_acpi_init(HVA address);
ACPI_TABLE_HEADER * vmm_acpi_locate_table(char *sig);
UINT16  vmm_acpi_smi_cmd_port(void);
UINT8   vmm_acpi_pm_port_size(void);
UINT32  vmm_acpi_pm_port_a(void);
UINT32  vmm_acpi_pm_port_b(void);
unsigned vmm_acpi_sleep_type_to_state(unsigned pm_reg_id, unsigned sleep_type);
int     vmm_acpi_waking_vector(UINT32 *p_waking_vector, UINT64 *p_extended_waking_vector);

typedef void (*vmm_acpi_callback)(void);
BOOLEAN vmm_acpi_register_platform_suspend_callback(vmm_acpi_callback suspend_cb);
BOOLEAN vmm_acpi_register_platform_resume_callback(vmm_acpi_callback resume_cb);

#endif // _ACPI_H_

