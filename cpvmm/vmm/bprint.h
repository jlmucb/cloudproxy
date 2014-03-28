/*
 * bprintk.h: printk to vga for bootstrap
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#ifndef __BPRINTK_H__
#define __BPRINTK_H__

#define VGA_BASE                    0xb8000

/* 80*25 text mode*/
#define MAX_LINES                   25
#define MAX_COLS                    80
#define SCREEN_BUFFER               (MAX_LINES*MAX_COLS*2)
#define VGA_ADDR(x, y)              (VGA_BASE + 2*(MAX_COLS*(y) + (x)))

/* registers */
#define CTL_ADDR_REG                0x3D4
#define CTL_DATA_REG                0x3D5
#define START_ADD_HIGH_REG          0x0C
#define START_ADD_LOW_REG           0x0D

/* colors */
#define COLOR_BLACK                 0x00
#define COLOR_BLUE                  0x01
#define COLOR_GREEN                 0x02
#define COLOR_CYAN                  0x03
#define COLOR_RED                   0x04
#define COLOR_MAGENTA               0x05
#define COLOR_BROWN                 0x06
#define COLOR_LTGRAY                0x07
#define COLOR_DKGRAY                0x08
#define COLOR_LTBLUE                0x09
#define COLOR_LTGREEN               0x0A
#define COLOR_LTCYAN                0x0B
#define COLOR_LTRED                 0x0C
#define COLOR_LTMAGENTA             0x0D
#define COLOR_LTBROWN               0x0E
#define COLOR_WHITE                 0x0F

#define COLOR                       ((COLOR_BLACK << 4) | COLOR_LTGRAY)

void vga_init(void);
void vga_puts(const char *s, unsigned int cnt);


#define TBOOT_LOG_LEVEL_NONE    0x00
#define TBOOT_LOG_LEVEL_ERR     0x01
#define TBOOT_LOG_LEVEL_WARN    0x02
#define TBOOT_LOG_LEVEL_INFO    0x04
#define TBOOT_LOG_LEVEL_DETA    0x08
#define TBOOT_LOG_LEVEL_ALL     0xFF

#define TBOOT_LOG_TARGET_NONE   0x00
#define TBOOT_LOG_TARGET_VGA    0x01
#define TBOOT_LOG_TARGET_SERIAL 0x02
#define TBOOT_LOG_TARGET_MEMORY 0x04

/*
extern uint8_t g_log_level;
extern uint8_t g_log_targets;
extern uint8_t g_vga_delay;
extern serial_port_t g_com_port;

#define serial_init()         comc_init()
#define serial_write(s, n)    comc_puts(s, n)
*/

#define vga_write(s,n)        vga_puts(s, n)

extern void printk_init(void);
extern void printk(const char *fmt, ...)
                         __attribute__ ((format (printf, 1, 2)));

#endif
