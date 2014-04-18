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

#ifndef _VMM_SERIAL_H_
#define _VMM_SERIAL_H_

#include "uart.h"

// Initialize a new serial device's parameters

void *                                  // Ret: Handle to the device
vmm_serial_new(
    UINT16              io_base,        // In:  I/O Base Address
    UART_PROG_IF_TYPE   prog_if,        // In:  Programming interface
    UART_HANDSHAKE_MODE handshake_mode  // In:  Handshake mode
);


// Initialize a serial device
    
void
vmm_serial_init(void   *h_device);   // In:  Handle of the device

void vmm_serial_reset(void *h_device);

// Returns the I/O range occupied by the device

void
vmm_serial_get_io_range(void   *h_device,    // In:  Handle of the device
                        UINT16 *p_io_base,   // Out: Base of I/O range
                        UINT16 *p_io_end);   // Out: End of I/O range

//
// Write a single character to a serial device in a non-locked mode.
// This function is reentrant, and can be safely called even while the normal
// vmm_serial_putc() runs.  However, it is not optimized for performance and
// should only be used when necessary, e.g., from an exception handler.

char                                     // Ret: Character that was sent
vmm_serial_putc_nolock(void *h_device,   // In:  Handle of the device
                       char  c);         // In:  Character to send


// Write a single character to a serial device.
// This function is not reentrant, and is for use in the normal case, where the
// serial device has been previously locked.  It may be interrupted by
// vmm_serial_putc_nolock().  The function attempts to use the full depth of
// the UART's transmit FIFO to avoid busy loops.

char                              // Ret: Character that was sent
vmm_serial_putc(void *h_device,   // In:  Handle of the device
                char  c);         // In:  Character to send


// Write a string to a serial device in a non-locked mode.
// This function is reentrant, and can be safely called even while the normal
// vmm_serial_putc() runs.  However, it should be used only when necessary,
// e.g. from an exception handler.

int                                            // Ret: 0 if failed
vmm_serial_puts_nolock(void       *h_device,   // In:  Handle of the device
                       const char  string[]);  // In:  String to send


// Write a string to a serial device
// This function is not reentrant, and is for use in the normal case, where the
// serial device has been previously locked.  It may be interrupted by
// vmm_serial_put*_nolock().

int                                     // Ret: 0 if failed
vmm_serial_puts(void       *h_device,   // In:  Handle of the device
                const char  string[]);   // In:  String to send


// Poll the serial device and read a single character if ready.
// This function is not reentrant.  Calling it while it runs in another thread
// may result in a junk character returned, but the s/w will not crash.

char                              // Ret: Character read from the device, 0 if
                                  //      none.
vmm_serial_getc(void *h_device);  // In:  Handle of the device

// Initialize CLI command(s) for serial ports
void vmm_serial_cli_init(void);

#endif
