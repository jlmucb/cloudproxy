/*
 * e820.c: support functions for manipulating the e820 table
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

typedef long long unsigned uint64_t;
typedef unsigned uint32_t;
typedef short unsigned uint16_t;
typedef unsigned char uint8_t;
typedef short unsigned u16;
typedef unsigned char u8;
typedef int bool;

#include "multiboot.h"
#include <e820.h>

#ifndef false
#define false 0
#define true 1
#endif

#ifndef NULL
#define NULL 0
#endif

typedef void (*tboot_printk)(const char *fmt, ...);
extern tboot_printk tprintk;

/*
 * copy of bootloader/BIOS e820 table with adjusted entries
 * this version will replace original in mbi
 */
static unsigned int max_e820_entries= 0;
static unsigned int g_nr_map= 0;
static memory_map_t *g_copy_e820_map = NULL;

static inline void split64b(uint64_t val, uint32_t *val_lo, uint32_t *val_hi)
{
    *val_lo = (uint32_t)(val & 0xffffffff);
    *val_hi = (uint32_t)(val >> 32);
}

static inline uint64_t combine64b(uint32_t val_lo, uint32_t val_hi)
{
    return ((uint64_t)val_hi << 32) | (uint64_t)val_lo;
}

static inline uint64_t e820_base_64(memory_map_t *entry)
{
    return combine64b(entry->base_addr_low, entry->base_addr_high);
}

static inline uint64_t e820_length_64(memory_map_t *entry)
{
    return combine64b(entry->length_low, entry->length_high);
}


void set_e820_copy_location(uint32_t place, uint32_t num)
{
    g_copy_e820_map = (memory_map_t *) place;
    max_e820_entries= num;
}

uint32_t get_num_e820_ents()
{
    return g_nr_map;
}


/*
 * print_e820_map
 * Prints copied e820 map w/o any header (i.e. just entries, indented by a tab)
 */
static void print_map(memory_map_t *e820, int nr_map)
{
    int i;
    for ( i = 0; i < nr_map; i++ ) {
        memory_map_t *entry = &e820[i];
        uint64_t base_addr, length;

        base_addr = e820_base_64(entry);
        length = e820_length_64(entry);

        tprintk("\t%016Lx - %016Lx  (%d)\n",
               (unsigned long long)base_addr,
               (unsigned long long)(base_addr + length),
               entry->type);
    }
}

static bool insert_after_region(memory_map_t *e820map, unsigned int *nr_map,
                                unsigned int pos, uint64_t addr, uint64_t size,
                                uint32_t type)
{
    unsigned int i;

    /* no more room */
    if ( *nr_map + 1 > max_e820_entries)
        return false;

    /* shift (copy) everything up one entry */
    for ( i = *nr_map - 1; i > pos; i--)
        e820map[i+1] = e820map[i];

    /* now add our entry */
    split64b(addr, &(e820map[pos+1].base_addr_low),
             &(e820map[pos+1].base_addr_high));
    split64b(size, &(e820map[pos+1].length_low),
             &(e820map[pos+1].length_high));
    e820map[pos+1].type = type;
    e820map[pos+1].size = sizeof(memory_map_t) - sizeof(uint32_t);

    (*nr_map)++;

    return true;
}

static void remove_region(memory_map_t *e820map, unsigned int *nr_map,
                          unsigned int pos)
{
    unsigned int i;

    /* shift (copy) everything down one entry */
    for ( i = pos; i < *nr_map - 1; i++)
        e820map[i] = e820map[i+1];

    (*nr_map)--;
}

static bool protect_region(memory_map_t *e820map, unsigned int *nr_map,
                           uint64_t new_addr, uint64_t new_size,
                           uint32_t new_type)
{
    uint64_t addr, tmp_addr, size, tmp_size;
    uint32_t type;
    unsigned int i;

    if ( new_size == 0 )
        return true;
    /* check for wrap */
    if ( new_addr + new_size < new_addr )
        return false;

    /* find where our region belongs in the table and insert it */
    for ( i = 0; i < *nr_map; i++ ) {
        addr = e820_base_64(&e820map[i]);
        size = e820_length_64(&e820map[i]);
        type = e820map[i].type;
        /* is our region at the beginning of the current map region? */
        if ( new_addr == addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return false;
            break;
        }
        /* are we w/in the current map region? */
        else if ( new_addr > addr && new_addr < (addr + size) ) {
            if ( !insert_after_region(e820map, nr_map, i, new_addr, new_size,
                                      new_type) )
                return false;
            /* fixup current region */
            tmp_addr = e820_base_64(&e820map[i]);
            split64b(new_addr - tmp_addr, &(e820map[i].length_low),
                     &(e820map[i].length_high));
            i++;   /* adjust to always be that of our region */
            /* insert a copy of current region (before adj) after us so */
            /* that rest of code can be common with previous case */
            if ( !insert_after_region(e820map, nr_map, i, addr, size, type) )
                return false;
            break;
        }
        /* is our region in a gap in the map? */
        else if ( addr > new_addr ) {
            if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                      new_type) )
                return false;
            break;
        }
    }
    /* if we reached the end of the map without finding an overlapping */
    /* region, insert us at the end (note that this test won't trigger */
    /* for the second case above because the insert() will have incremented */
    /* nr_map and so i++ will still be less) */
    if ( i == *nr_map ) {
        if ( !insert_after_region(e820map, nr_map, i-1, new_addr, new_size,
                                  new_type) )
            return false;
        return true;
    }

    i++;     /* move to entry after our inserted one (we're not at end yet) */

    tmp_addr = e820_base_64(&e820map[i]);
    tmp_size = e820_length_64(&e820map[i]);

    /* did we split the (formerly) previous region? */
    if ( (new_addr >= tmp_addr) &&
         ((new_addr + new_size) < (tmp_addr + tmp_size)) ) {
        /* then adjust the current region (adj size first) */
        split64b((tmp_addr + tmp_size) - (new_addr + new_size),
                 &(e820map[i].length_low), &(e820map[i].length_high));
        split64b(new_addr + new_size,
                 &(e820map[i].base_addr_low), &(e820map[i].base_addr_high));
        return true;
    }

    /* if our region completely covers any existing regions, delete them */
    while ( (i < *nr_map) && ((new_addr + new_size) >=
                              (tmp_addr + tmp_size)) ) {
        remove_region(e820map, nr_map, i);
        tmp_addr = e820_base_64(&e820map[i]);
        tmp_size = e820_length_64(&e820map[i]);
    }

    /* finally, if our region partially overlaps an existing region, */
    /* then truncate the existing region */
    if ( i < *nr_map ) {
        tmp_addr = e820_base_64(&e820map[i]);
        tmp_size = e820_length_64(&e820map[i]);
        if ( (new_addr + new_size) > tmp_addr ) {
            split64b((tmp_addr + tmp_size) - (new_addr + new_size),
                        &(e820map[i].length_low), &(e820map[i].length_high));
            split64b(new_addr + new_size, &(e820map[i].base_addr_low),
                        &(e820map[i].base_addr_high));
        }
    }

    return true;
}

/*
 * is_overlapped
 *
 * Detect whether two ranges are overlapped.
 *
 * return: true = overlapped
 */
static bool is_overlapped(uint64_t base, uint64_t end, uint64_t e820_base,
                          uint64_t e820_end)
{
    uint64_t length = end - base, e820_length = e820_end - e820_base;
    uint64_t min, max;

    min = (base < e820_base)?base:e820_base;
    max = (end > e820_end)?end:e820_end;

    /* overlapping */
    if ( (max - min) < (length + e820_length) )
        return true;

    if ( (max - min) == (length + e820_length)
         && ( ((length == 0) && (base > e820_base) && (base < e820_end))
              || ((e820_length == 0) && (e820_base > base) &&
                  (e820_base < end)) ) )
        return true;

    return false;
}

/*
 * copy_e820_map
 * Copies the raw e820 map from bootloader to new table with room for expansion
 * return:  false = error (no table or table too big for new space)
 */
bool copy_e820_map(const multiboot_info_t *mbi)
{
    g_nr_map = 0;

    if ( mbi->flags & MBI_MEMMAP ) {
        tprintk("original e820 map:\n");
        print_map((memory_map_t *)mbi->mmap_addr,
                  mbi->mmap_length/sizeof(memory_map_t));

        uint32_t entry_offset = 0;

        while ( entry_offset < mbi->mmap_length &&
                g_nr_map < max_e820_entries) {
            memory_map_t *entry = (memory_map_t *)
                                       (mbi->mmap_addr + entry_offset);

            /* we want to support unordered and/or overlapping entries */
            /* so use protect_region() to insert into existing map, since */
            /* it handles these cases */
            if ( !protect_region(g_copy_e820_map, &g_nr_map,
                                 e820_base_64(entry), e820_length_64(entry),
                                 entry->type) )
                return false;
            entry_offset += entry->size + sizeof(entry->size);
        }
        if ( g_nr_map == max_e820_entries) {
            tprintk("Too many e820 entries\n");
            return false;
        }
    }
    else if ( mbi->flags & MBI_MEMLIMITS ) {
        tprintk("no e820 map, mem_lower=%x, mem_upper=%x\n",
               mbi->mem_lower, mbi->mem_upper);

        /* lower limit is 0x00000000 - <mem_lower>*0x400 (i.e. in kb) */
        g_copy_e820_map[0].base_addr_low = 0;
        g_copy_e820_map[0].base_addr_high = 0;
        g_copy_e820_map[0].length_low = mbi->mem_lower << 10;
        g_copy_e820_map[0].length_high = 0;
        g_copy_e820_map[0].type = E820_RAM;
        g_copy_e820_map[0].size = sizeof(memory_map_t) - sizeof(uint32_t);

        /* upper limit is 0x00100000 - <mem_upper>*0x400 */
        g_copy_e820_map[1].base_addr_low = 0x100000;
        g_copy_e820_map[1].base_addr_high = 0;
        split64b((uint64_t)mbi->mem_upper << 10,
                 &(g_copy_e820_map[1].length_low),
                 &(g_copy_e820_map[1].length_high));
        g_copy_e820_map[1].type = E820_RAM;
        g_copy_e820_map[1].size = sizeof(memory_map_t) - sizeof(uint32_t);

        g_nr_map = 2;
    }
    else {
        tprintk("no e820 map nor memory limits provided\n");
        return false;
    }

    return true;
}

void replace_e820_map(multiboot_info_t *mbi)
{
    /* replace original with the copy */
    mbi->mmap_addr = (uint32_t)g_copy_e820_map;
    mbi->mmap_length = g_nr_map * sizeof(memory_map_t);
    mbi->flags |= MBI_MEMMAP;   /* in case only MBI_MEMLIMITS was set */
}

bool e820_protect_region(uint64_t addr, uint64_t size, uint32_t type)
{
    return protect_region(g_copy_e820_map, &g_nr_map, addr, size, type);
}

/*
 * e820_check_region
 *
 * Given a range, check which kind of range it covers
 *
 * return: E820_GAP, it covers gap in e820 map;
 *         E820_MIXED, it covers at least two different kinds of ranges;
 *         E820_XXX, it covers E820_XXX range only;
 *         it will not return 0.
 */
uint32_t e820_check_region(uint64_t base, uint64_t length)
{
    memory_map_t* e820_entry;
    uint64_t end = base + length, e820_base, e820_end, e820_length;
    uint32_t type;
    uint32_t ret = 0;
    bool gap = true; /* suppose there is always a virtual gap at first */
    unsigned int i;

    e820_base = 0;
    e820_length = 0;

    for ( i = 0; i < g_nr_map; i = gap ? i : i+1, gap = !gap ) {
        e820_entry = &g_copy_e820_map[i];
        if ( gap ) {
            /* deal with the gap in e820 map */
            e820_base = e820_base + e820_length;
            e820_length = e820_base_64(e820_entry) - e820_base;
            type = E820_GAP;
        }
        else {
            /* deal with the normal item in e820 map */
            e820_base = e820_base_64(e820_entry);
            e820_length = e820_length_64(e820_entry);
            type = e820_entry->type;
        }

        if ( e820_length == 0 )
            continue; /* if the range is zero, then skip */

        e820_end = e820_base + e820_length;

        if ( !is_overlapped(base, end, e820_base, e820_end) )
            continue; /* if no overlapping, then skip */

        /* if the value of ret is not assigned before,
           then set ret to type directly */
        if ( ret == 0 ) {
            ret = type;
            continue;
        }

        /* if the value of ret is assigned before but ret is equal to type,
           then no need to do anything */
        if ( ret == type )
            continue;

        /* if the value of ret is assigned before but it is GAP,
           then no need to do anything since any type merged with GAP is GAP */
        if ( ret == E820_GAP )
            continue;

        /* if the value of ret is assigned before but it is not GAP and type
           is GAP now this time, then set ret to GAP since any type merged
           with GAP is GAP. */
        if ( type == E820_GAP ) {
            ret = E820_GAP;
            continue;
        }

        /* if the value of ret is assigned before but both ret and type are
           not GAP and their values are not equal, then set ret to MIXED
           since any two non-GAP values are merged into MIXED if they are
           not equal. */
        ret = E820_MIXED;
    }

    /* deal with the last gap */
    if ( is_overlapped(base, end, e820_base + e820_length, (uint64_t)-1) )
        ret = E820_GAP;

    /* print the result */
    tprintk(" (range from %016Lx to %016Lx is in ", base, base + length);
    switch (ret) {
        case E820_RAM:
            tprintk("E820_RAM)\n"); break;
        case E820_RESERVED:
            tprintk("E820_RESERVED)\n"); break;
        case E820_ACPI:
            tprintk("E820_ACPI)\n"); break;
        case E820_NVS:
            tprintk("E820_NVS)\n"); break;
        case E820_UNUSABLE:
            tprintk("E820_UNUSABLE)\n"); break;
        case E820_GAP:
            tprintk("E820_GAP)\n"); break;
        case E820_MIXED:
            tprintk("E820_MIXED)\n"); break;
        default:
            tprintk("UNKNOWN)\n");
    }

    return ret;
}

/*
 * e820_reserve_ram
 * Given the range, any ram range in e820 is in it, change type to reserved.
 * return:  false = error
 */
bool e820_reserve_ram(uint64_t base, uint64_t length)
{
    memory_map_t* e820_entry;
    uint64_t e820_base, e820_length, e820_end;
    uint64_t end;
    unsigned int i;

    if ( length == 0 )
        return true;

    end = base + length;

    /* find where our region should cover the ram in e820 */
    for ( i = 0; i < g_nr_map; i++ ) {
        e820_entry = &g_copy_e820_map[i];
        e820_base = e820_base_64(e820_entry);
        e820_length = e820_length_64(e820_entry);
        e820_end = e820_base + e820_length;

        /* if not ram, no need to deal with */
        if ( e820_entry->type != E820_RAM )
            continue;

        /* if the range is before the current ram range, skip the ram range */
        if ( end <= e820_base )
            continue;
        /* if the range is after the current ram range, skip the ram range */
        if ( base >= e820_end )
            continue;

        /* case 1: the current ram range is within the range:
           base, e820_base, e820_end, end */
        if ( (base <= e820_base) && (e820_end <= end) )
            e820_entry->type = E820_RESERVED;
        /* case 2: overlapping:
           base, e820_base, end, e820_end */
        else if ( (e820_base >= base) && (end > e820_base) &&
                  (e820_end > end) ) {
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i-1,
                                      e820_base, (end - e820_base),
                                      E820_RESERVED) )
                return false;
            /* fixup the current ram map */
            i++;
            split64b(end, &(g_copy_e820_map[i].base_addr_low),
                     &(g_copy_e820_map[i].base_addr_high));
            split64b(e820_end - end, &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* no need to check more */
            break;
        }
        /* case 3: overlapping:
           e820_base, base, e820_end, end */
        else if ( (base > e820_base) && (e820_end > base) &&
                  (end >= e820_end) ) {
            /* fixup the current ram map */
            split64b((base - e820_base), &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, base,
                                      (e820_end - base), E820_RESERVED) )
                return false;
            i++;
        }
        /* case 4: the range is within the current ram range:
           e820_base, base, end, e820_end */
        else if ( (base > e820_base) && (e820_end > end) ) {
            /* fixup the current ram map */
            split64b((base - e820_base), &(g_copy_e820_map[i].length_low),
                     &(g_copy_e820_map[i].length_high));
            /* split the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, base,
                                      length, E820_RESERVED) )
                return false;
            i++;
            /* fixup the rest of the current ram map */
            if ( !insert_after_region(g_copy_e820_map, &g_nr_map, i, end,
                                      (e820_end - end), e820_entry->type) )
                return false;
            i++;
            /* no need to check more */
            break;
        }
        else {
            tprintk("we should never get here\n");
            return false;
        }
    }

    return true;
}

void print_e820_map(void)
{
    print_map(g_copy_e820_map, g_nr_map);
}

bool get_ram_ranges(uint64_t *min_lo_ram, uint64_t *max_lo_ram,
                    uint64_t *min_hi_ram, uint64_t *max_hi_ram)
{
    if ( min_lo_ram == NULL || max_lo_ram == NULL ||
         min_hi_ram == NULL || max_hi_ram == NULL )
        return false;

    *min_lo_ram = *min_hi_ram = ~0ULL;
    *max_lo_ram = *max_hi_ram = 0;
    bool found_reserved_region = false;
    unsigned int i;

    for ( i = 0; i < g_nr_map; i++ ) {
        memory_map_t *entry = &g_copy_e820_map[i];
        uint64_t base = e820_base_64(entry);
        uint64_t limit = base + e820_length_64(entry);

        if ( entry->type == E820_RAM ) {
            /* if range straddles 4GB boundary, that is an error */
            if ( base < 0x100000000ULL && limit > 0x100000000ULL ) {
                tprintk("e820 memory range straddles 4GB boundary\n");
                return false;
            }

            /*
             * some BIOSes put legacy USB buffers in reserved regions <4GB,
             * which if DMA protected cause SMM to hang, so make sure that
             * we don't overlap any of these even if that wastes RAM
             */
            if ( !found_reserved_region ) {
                if ( base < 0x100000000ULL && base < *min_lo_ram )
                    *min_lo_ram = base;
                if ( limit <= 0x100000000ULL && limit > *max_lo_ram )
                    *max_lo_ram = limit;
            }
            else {     /* need to reserve low RAM above reserved regions */
                if ( base < 0x100000000ULL ) {
                    tprintk("discarding RAM above reserved regions: 0x%Lx - 0x%Lx\n", base, limit);
                    if ( !e820_reserve_ram(base, limit - base) )
                        return false;
                }
            }

            if ( base >= 0x100000000ULL && base < *min_hi_ram )
                *min_hi_ram = base;
            if ( limit > 0x100000000ULL && limit > *max_hi_ram )
                *max_hi_ram = limit;
        }
        else {
            /* parts of low memory may be reserved for cseg, ISA hole,
               etc. but these seem OK to DMA protect, so ignore reserved
               regions <0x100000 */
            if ( *min_lo_ram != ~0ULL && limit > 0x100000ULL )
                found_reserved_region = true;
        }
    }

    /* no low RAM found */
    if ( *min_lo_ram >= *max_lo_ram ) {
        tprintk("no low ram in e820 map\n");
        return false;
    }
    /* no high RAM found */
    if ( *min_hi_ram >= *max_hi_ram )
        *min_hi_ram = *max_hi_ram = 0;

    return true;
}

/* find highest (< <limit>) RAM region of at least <size> bytes */
void get_highest_sized_ram(uint64_t size, uint64_t limit,
                           uint64_t *ram_base, uint64_t *ram_size)
{
    uint64_t last_fit_base = 0, last_fit_size = 0;
    unsigned int i;

    if ( ram_base == NULL || ram_size == NULL )
        return;

    for ( i = 0; i < g_nr_map; i++ ) {
        memory_map_t *entry = &g_copy_e820_map[i];

        if ( entry->type == E820_RAM ) {
            uint64_t base = e820_base_64(entry);
            uint64_t length = e820_length_64(entry);

            /* over 4GB so use the last region that fit */
            if ( base + length > limit )
                break;
            if ( size <= length ) {
                last_fit_base = base;
                last_fit_size = length;
            }
        }
    }

    *ram_base = last_fit_base;
    *ram_size = last_fit_size;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
