/*
 * multiboot.h:  definitions for the multiboot bootloader specification
 *
 * Copyright (c) 2010, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __MULTIBOOT_H__
#define __MULTIBOOT_H__

#include <config.h>

/* Multiboot Header Definitions of OS image*/
#define MULTIBOOT_HEADER_MAGIC			0x1BADB002
/* Bit definitions of flags field of multiboot header*/
#define MULTIBOOT_HEADER_MODS_ALIGNED	0x1
#define MULTIBOOT_HEADER_WANT_MEMORY	0x2

/* bit definitions of flags field of multiboot information */
#define MBI_MEMLIMITS    (1<<0)
#define MBI_BOOTDEV      (1<<1)
#define MBI_CMDLINE      (1<<2)
#define MBI_MODULES      (1<<3)
#define MBI_AOUT         (1<<4)
#define MBI_ELF          (1<<5)
#define MBI_MEMMAP       (1<<6)
#define MBI_DRIVES       (1<<7)
#define MBI_CONFIG       (1<<8)
#define MBI_BTLDNAME     (1<<9)
#define MBI_APM          (1<<10)
#define MBI_VBE          (1<<11)

#ifndef __ASSEMBLY__

typedef struct {
    uint32_t tabsize;
    uint32_t strsize;
    uint32_t addr;
    uint32_t reserved;
} aout_t; /* a.out kernel image */

typedef struct {
    uint32_t num;
    uint32_t size;
    uint32_t addr;
    uint32_t shndx;
} elf_t; /* elf kernel */

typedef struct {
    uint8_t bios_driver;
    uint8_t top_level_partition;
    uint8_t sub_partition;
    uint8_t third_partition;
} boot_device_t;

typedef struct {
    uint32_t flags;

    /* valid if flags[0] (MBI_MEMLIMITS) set */
    uint32_t mem_lower;
    uint32_t mem_upper;

    /* valid if flags[1] set */
    boot_device_t boot_device;

    /* valid if flags[2] (MBI_CMDLINE) set */
    uint32_t cmdline;

    /* valid if flags[3] (MBI_MODS) set */
    uint32_t mods_count;
    uint32_t mods_addr;

    /* valid if flags[4] or flags[5] set */
    union {
        aout_t aout_image;
        elf_t  elf_image;
    } syms;

    /* valid if flags[6] (MBI_MEMMAP) set */
    uint32_t mmap_length;
    uint32_t mmap_addr;

    /* valid if flags[7] set */
    uint32_t drives_length;
    uint32_t drives_addr;

    /* valid if flags[8] set */
    uint32_t config_table;

    /* valid if flags[9] set */
    uint32_t boot_loader_name;

    /* valid if flags[10] set */
    uint32_t apm_table;

    /* valid if flags[11] set */
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
} multiboot_info_t;

typedef struct {
	uint32_t mod_start;
	uint32_t mod_end;
	uint32_t string;
	uint32_t reserved;
} module_t;

typedef struct {
	uint32_t size;
	uint32_t base_addr_low;
	uint32_t base_addr_high;
	uint32_t length_low;
	uint32_t length_high;
	uint32_t type;
} memory_map_t;

extern unsigned long get_mbi_mem_end(const multiboot_info_t *mbi);

#endif /* __ASSEMBLY__ */

#endif /* __MULTIBOOT_H__ */

