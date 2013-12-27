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

#include "vmm_defs.h"
#include "vmm_serial.h"
#include "hw_utils.h"
#include "vmm_dbg.h"
#include "cli.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMM_SERIAL_LIBC)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMM_SERIAL_LIBC, __condition)


//==============================================================================
//
// Private Definitions
//
//==============================================================================

#define VMM_SERIAL_DEVICES_MAX 8

typedef struct
{
    UINT16              io_base;
    UINT8               reserved[2];
    UART_PROG_IF_TYPE   prog_if;
    UART_HANDSHAKE_MODE handshake_mode;
                                 // Handshake mode, as set on initialization
    UINT32              hw_fifo_size;
                                 // FIFO size of the UART h/w.  Set according to
                                 // prog_if.
    UINT32              chars_in_tx_fifo;
                                 // Current # of chars in h/w transmit FIFO.
                                 // Note that this is a maximum estimate, actual
                                 // number may be lower - this is the case where
                                 // vmm_serial_putc() is interrupted by
                                 // vmm_serial_putc_nolock().
    BOOLEAN             puts_lock;
                                 // Used by puts_nolocked() to lock out regular
                                 // prints
    BOOLEAN             in_putc; // Flags that putc() is executing
    BOOLEAN             in_puts; // Flags that puts() is executing
    UINT32              hw_handshake_stopped_count;
                                 // Counts the number of consecutive times h/w
                                 // handshake has been found to be "stop"
    BOOLEAN             is_initialized;
                                 // Indicates that the device has been
                                 // initialized.  Used for sanity checks.

    // Statistics - Used Mainly for Debug

    UINT32              num_tx_chars_lock;
    UINT32              num_tx_chars_nolock;
                                 // Counters of transmitted characters in locked
                                 // mode (normal) and nolock mode
    UINT32              num_rx_chars;
                                 // Counter of received characters
    UINT32              wait_for_tx_ready_max;
                                 // Max number of times tx paused until tx
                                 // ready (for any reason).
    UINT32              wait_for_tx_ready_avg;
                                 // Average number of times tx paused until tx
                                 // ready (for any reason).  In units of
                                 // 1 / 2^16 (i.e., upper 16 bits is the whole
                                 // number part, lower 16 bit is the fraction
    UINT32              wait_for_tx_fifo_empty_max;
                                 // Max number of times tx paused until tx
                                 // FIFO was empty.  In units of
    UINT32              wait_for_tx_fifo_empty_avg;
                                 // Average number of times tx paused until tx
                                 // FIFO was empty.  In units of
                                 // 1 / 2^16 (i.e., upper 16 bits is the whole
                                 // number part, lower 16 bit is the fraction
                                 // part).
    UINT32              num_puts_interrupted_by_putc_nolock;
    UINT32              num_puts_interrupted_by_puts_nolock;
                                 // Count the number of times the normal puts()
                                 // was interrupted by puts_nolock() and
                                 // puts_nolock()
    UINT32              num_putc_blocked_by_puts_nolock;
                                 // Counts the number of times the normal putc()
                                 // was blocked by puts_nolock()
    UINT32              num_chars_hw_handshake_stopped;
                                 // Number of characters for which tx stopped
                                 // due to h/w handshake
    UINT32              num_chars_hw_handshake_auto_go;
                                 // Number of characters for which tx h/w
                                 // handshake stop was auto-released
    UINT32              hw_handshake_stopped_count_max;
                                 // Maximum value of hw_handshake_stopped_count,
                                 // for statistics & debug
    UINT32              hw_handshake_stopped_count_avg;
                                 // Average value of hw_handshake_stopped_count,
                                 // for statistics & debug.  In units of
                                 // 1 / 2^16 (i.e., upper 16 bits is the whole
                                 // number part, lower 16 bit is the fraction
                                 // part).
} VMM_SERIAL_DEVICE;


//==============================================================================
//
// Static Variables
//
//==============================================================================

static VMM_SERIAL_DEVICE serial_devices[VMM_SERIAL_DEVICES_MAX];
static UINT32            initialized_serial_devices = 0;
static const UINT32      serial_tx_stall_usec       = 100;
                                 // Number of usecs to stall between tx
                                 // attempts if not ready.  at 115200 baud,
                                 // each character is about 87 usec.
                                 // TODO: tune for tx fifo size
static const UINT32      hw_handshake_stopped_limit = 50000;   // 5 sec
                                 // In auto mode, number of stalls at h/w
                                 // handshake stop until thestatus is
                                 // considered "go"
static const UINT32      avg_factor = 16;
                                 // Factor for averaging pause counters.  In
                                 // units of 1 / 2^16


//=============================================================================
//
// Static Functions
//
//=============================================================================

//=============================== update_max() ================================
//
// Updates the maximum of a counter

static
void
update_max(UINT32 *p_max,   // Maximum
           UINT32  count)   // New input

{
    if (count > *p_max)
        *p_max = count;
}


//=============================== update_avg() ================================
//
// Updates the running average of a counter, using a simple 1-stage IIR
// algorithm

static
void
update_avg(UINT32 *p_avg,   // Running average, as UINT16.UINT16
           UINT32  count)   // New input

{
    UINT64       avg;


    // Extend to 64 bits to prevent overflow during calculation

    avg = (UINT64)(*p_avg);

    // Do the IIR.  The formula is:
    //    avg = (1 - f) * avg + f * counter
    // Here the calculation is factored to UINT48.UINT16 representation

    avg = ((((1 << 16) - avg_factor) *                   avg) +
           (             avg_factor  * ((UINT64)count << 16))
          ) >> 16;

    // Assign back, taking care of overflows

    if (avg > (UINT32)-1)
        *p_avg = (UINT32)-1;
    else
        *p_avg = (UINT32)avg;
}


//========================= update_max_and_avg() ==============================
//
// Updates the running average and maximum of a counter
static
void
update_max_and_avg(UINT32 *p_max,   // Maximum
                   UINT32 *p_avg,   // Running average, as UINT16.UINT16
                   UINT32  count)   // New input

{
    update_max(p_max, count);
    update_avg(p_avg, count);
}


//========================= is_hw_tx_handshake_go() ===========================
//
// Checks h/w handshake lines for "go" status.  Count the number of times it
// was "stop".  In UART_HANDSHAKE_AUTO mode, after a limit is reached force
// the status to "go".

static
BOOLEAN
is_hw_tx_handshake_go(VMM_SERIAL_DEVICE *p_device)

{
    UART_MSR msr;               // Modem Status Register image
    BOOLEAN  hw_handshake_go;   // Flags transmit "go" by h/w handshake


    if ((p_device->handshake_mode == UART_HANDSHAKE_AUTO) ||
        (p_device->handshake_mode == UART_HANDSHAKE_HW))
    {
        // Read the h/w handshake signals

        msr.data = hw_read_port_8(p_device->io_base + UART_REGISTER_MSR);
        hw_handshake_go = (msr.bits.CTS == 1) && (msr.bits.DSR == 1);

        if (hw_handshake_go)
        {
            // Other side set h/w handshake to "go".  Reset the counter.

            update_avg(&p_device->hw_handshake_stopped_count_avg,
                       p_device->hw_handshake_stopped_count);
            p_device->hw_handshake_stopped_count = 0;
        }

        else if (p_device->hw_handshake_stopped_count >=
                                                    hw_handshake_stopped_limit)
        {
            // Other side has indicated h/w handshake "stop" for too long.

            if (p_device->handshake_mode == UART_HANDSHAKE_AUTO)
            {
                // In auto mode, assume the h/w handshake is stuck and force
                // the status to "go"

                hw_handshake_go = TRUE;
                p_device->num_chars_hw_handshake_auto_go++;
                if (p_device->hw_handshake_stopped_count ==
                                                    hw_handshake_stopped_limit)
                {
                    // Update the statistic only on the first character
                    // we decided to auto-go

                    update_avg(&p_device->hw_handshake_stopped_count_avg,
                               p_device->hw_handshake_stopped_count);
                    p_device->hw_handshake_stopped_count++;
                }
            }
        }

        else
        {
            // Increment the stop count and update the statistics

            if (p_device->hw_handshake_stopped_count == 0)
            {
                // We just stopped, increment the stops statistics counter

                p_device->num_chars_hw_handshake_stopped++;
            }

            p_device->hw_handshake_stopped_count++;

            update_max(&p_device->hw_handshake_stopped_count_max,
                       p_device->hw_handshake_stopped_count);
        }
    }

    else
    {
        // No h/w handshake, always "go"

        hw_handshake_go = TRUE;
    }

    return hw_handshake_go;
}


//====================== cli_display_serial_info() ============================
//
// Display serial ports' information on the CLI
#ifdef DEBUG
#pragma warning(push )
#pragma warning(disable : 4100)  // Supress warnings about unreferenced formal parameter
static
int
cli_display_serial_info(unsigned argc UNUSED, char *args[] UNUSED)
{
    UINT32 i;


    CLI_PRINT("Serial Device #                :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT("        %1d     ", i);

    CLI_PRINT("\nI/O Base                       :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT("   0x%04x     ", serial_devices[i].io_base);

    CLI_PRINT("\nChars Tx (lock)                :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ", serial_devices[i].num_tx_chars_lock);

    CLI_PRINT("\nChars Tx (nolock)              :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ", serial_devices[i].num_tx_chars_nolock);

    CLI_PRINT("\nChars Rx                       :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ", serial_devices[i].num_rx_chars);

    CLI_PRINT("\nTx Ready Wait Time (max)       :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d uSec",
                  serial_devices[i].wait_for_tx_ready_max *
                  serial_tx_stall_usec);

    CLI_PRINT("\nTx Ready Wait Time (avg)       :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d uSec",
                  (serial_devices[i].wait_for_tx_ready_avg >> 16) *
                  serial_tx_stall_usec);

    CLI_PRINT("\nTx FIFO Empty Wait Time (max)  :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d uSec",
                  serial_devices[i].wait_for_tx_fifo_empty_max *
                  serial_tx_stall_usec);

    CLI_PRINT("\nTx FIFO Empty Wait Time (avg)  :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d uSec",
                  (serial_devices[i].wait_for_tx_fifo_empty_avg >> 16) *
                  serial_tx_stall_usec);

    CLI_PRINT("\nTx H/S Mode                    :");
    for (i = 0; i < initialized_serial_devices; i++)
    {
        switch (serial_devices[i].handshake_mode)
        {
            case UART_HANDSHAKE_AUTO:
                if (serial_devices[i].hw_handshake_stopped_count <
                                           hw_handshake_stopped_limit)
                {
                    CLI_PRINT("     Auto-H/W ");
                }
                else
                {
                    CLI_PRINT("     Auto-None");
                }
                break;

            caseUART_HANDSHAKE_HW:
                CLI_PRINT("      H/W     ");
                break;

            case UART_HANDSHAKE_NONE:
                CLI_PRINT("     None     ");
                break;

            default:
                CLI_PRINT(" ?????????????");
        }
    }


    CLI_PRINT("\nTx H/S Stopped Chars           :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ",
                  serial_devices[i].num_chars_hw_handshake_stopped);

    CLI_PRINT("\nTx H/S Auto-Go Chars           :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ",
                  serial_devices[i].num_chars_hw_handshake_auto_go);

    CLI_PRINT("\nTx H/S Stopped Time (max)      :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d mSec",
                  serial_devices[i].hw_handshake_stopped_count_max *
                  serial_tx_stall_usec /
                  1000);

    CLI_PRINT("\nTx H/S Stopped Time (avg)      :");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d mSec",
                  (serial_devices[i].hw_handshake_stopped_count_avg >> 16) *
                  serial_tx_stall_usec /
                  1000);

    CLI_PRINT("\nString Tx inter. by putc_nolock:");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ",
                  serial_devices[i].num_puts_interrupted_by_putc_nolock);

    CLI_PRINT("\nString Tx inter. by puts_nolock:");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ",
                  serial_devices[i].num_puts_interrupted_by_puts_nolock);

    CLI_PRINT("\nChars Tx blocked by puts_nolock:");
    for (i = 0; i < initialized_serial_devices; i++)
        CLI_PRINT(" %8d     ",
                  serial_devices[i].num_putc_blocked_by_puts_nolock);

    CLI_PRINT("\n");

    return 0;
}
#pragma warning(pop)
#endif //DEBUG

//=============================================================================
//
// Public Functions
//
//=============================================================================

//=========================== vmm_serial_new() ================================
//
// Initialize a new serial device's parameters

void *                                  // Ret: Handle to the device
vmm_serial_new(
    UINT16              io_base,        // In:  I/O Base Address
    UART_PROG_IF_TYPE   prog_if,        // In:  Programming interface
    UART_HANDSHAKE_MODE handshake_mode  // In:  Handshake mode
)

{
    VMM_SERIAL_DEVICE *p_device;


    if (initialized_serial_devices >= VMM_SERIAL_DEVICES_MAX)
        return NULL;

    p_device = &serial_devices[initialized_serial_devices++];

    p_device->io_base = io_base;
    p_device->prog_if = prog_if;
    switch (prog_if)
    {
        case UART_PROG_IF_GENERIC:
        case UART_PROG_IF_16450  :
            p_device->hw_fifo_size = 1;
            break;

        case UART_PROG_IF_16550  :
        case UART_PROG_IF_16650  :
        case UART_PROG_IF_16750  :
        case UART_PROG_IF_16850  :
        case UART_PROG_IF_16950  :
            p_device->hw_fifo_size = 16;   // TODO: correct sizes
            break;

        default:
            return NULL;
    };
    p_device->chars_in_tx_fifo = p_device->hw_fifo_size;
                                    // This forces polling of the transmit
                                    // empty status bit
    p_device->handshake_mode = handshake_mode;

    p_device->num_tx_chars_lock = 0;
    p_device->num_tx_chars_nolock = 0;
    p_device->num_rx_chars = 0;

    p_device->wait_for_tx_ready_max = 0;
    p_device->wait_for_tx_ready_avg = 0;
    p_device->wait_for_tx_fifo_empty_max = 0;
    p_device->wait_for_tx_fifo_empty_avg = 0;

    p_device->puts_lock = FALSE;
    p_device->in_putc = FALSE;
    p_device->in_puts = FALSE;
    p_device->num_puts_interrupted_by_putc_nolock = 0;
    p_device->num_puts_interrupted_by_puts_nolock = 0;
    p_device->num_putc_blocked_by_puts_nolock = 0;

    p_device->num_chars_hw_handshake_stopped = 0;
    p_device->num_chars_hw_handshake_auto_go = 0;
    p_device->hw_handshake_stopped_count = 0;
    p_device->hw_handshake_stopped_count_max = 0;
    p_device->hw_handshake_stopped_count_avg = 0;

    p_device->is_initialized = FALSE;

    return p_device;
}


//=========================== vmm_serial_init() ===============================
//
// Initialize a serial device

void
vmm_serial_init(void   *h_device)   // In:  Handle of the device

{
    VMM_SERIAL_DEVICE *p_device;
    UART_IER           ier;
    UART_FCR           fcr;
    UART_LCR           lcr;
    UART_MCR           mcr;


    p_device = h_device;
    VMM_ASSERT(p_device);
    VMM_ASSERT(! p_device->is_initialized);

    // MCR: Reset DTR, RTS, Out1, Out2 & Loop

    mcr.bits.DTRC     = 0;
    mcr.bits.RTS      = 0;
    mcr.bits.OUT1     = 0;
    mcr.bits.OUT2     = 0;
    mcr.bits.LME      = 0;
    mcr.bits.Reserved = 0;
    hw_write_port_8(p_device->io_base + UART_REGISTER_MCR, mcr.data);

    // LCR: Reset DLAB

    lcr.bits.SERIALDB   = 0x03;   // 8 data bits
    lcr.bits.STOPB      = 0;      // 1 stop bit
    lcr.bits.PAREN      = 0;      // No parity
    lcr.bits.EVENPAR    = 0;      // N/A
    lcr.bits.STICPAR    = 0;      // N/A
    lcr.bits.BRCON      = 0;      // No break
    lcr.bits.DLAB       = 0;
    hw_write_port_8(p_device->io_base + UART_REGISTER_LCR, lcr.data);

    // IER: Disable interrupts

    ier.bits.RAVIE    = 0;
    ier.bits.THEIE    = 0;
    ier.bits.RIE      = 0;
    ier.bits.MIE      = 0;
    ier.bits.Reserved = 0;
    hw_write_port_8(p_device->io_base + UART_REGISTER_IER, ier.data);

    // FCR: Disable FIFOs

    fcr.bits.TRFIFOE  = 0;
    fcr.bits.RESETRF  = 0;
    fcr.bits.RESETTF  = 0;
    fcr.bits.DMS      = 0;
    fcr.bits.Reserved = 0;
    fcr.bits.RTB      = 0;
    hw_write_port_8(p_device->io_base + UART_REGISTER_FCR, fcr.data);

    // SCR: Scratch register

    hw_write_port_8(p_device->io_base + UART_REGISTER_SCR, 0x00);

    // LCR: Set DLAB

    lcr.bits.DLAB = 1;
    hw_write_port_8(p_device->io_base + UART_REGISTER_LCR, lcr.data);

    // DLL & DLM: Divisor value 1 for 115200 baud

    hw_write_port_8(p_device->io_base + UART_REGISTER_DLL, 0x01);
    hw_write_port_8(p_device->io_base + UART_REGISTER_DLM, 0x00);

    // LCR: Reset DLAB

    lcr.bits.DLAB = 0;
    hw_write_port_8(p_device->io_base + UART_REGISTER_LCR, lcr.data);

    // FCR: Enable and reset Rx & Tx FIFOs

    fcr.bits.TRFIFOE  = 1;
    fcr.bits.RESETRF  = 1;
    fcr.bits.RESETTF  = 1;
    hw_write_port_8(p_device->io_base + UART_REGISTER_FCR, fcr.data);

    // MCR: Set DTR, RTS

    mcr.bits.DTRC     = 1;
    mcr.bits.RTS      = 1;
    hw_write_port_8(p_device->io_base + UART_REGISTER_MCR, mcr.data);

    p_device->is_initialized = TRUE;
}

void vmm_serial_reset(void *h_device)
{
    VMM_SERIAL_DEVICE *p_device;

    p_device = h_device;
    p_device->is_initialized = FALSE;
}

//======================= vmm_serial_get_io_range() ===========================
//
// Returns the I/O range occupied by the device
void
vmm_serial_get_io_range(void   *h_device,   // In:  Handle of the device
                        UINT16 *p_io_base,  // Out: Base of I/O range
                        UINT16 *p_io_end)   // Out: End of I/O range

{
    VMM_SERIAL_DEVICE *p_device;


    p_device = h_device;

    *p_io_base = p_device->io_base;
    *p_io_end = p_device->io_base + 7;
}

//======================= vmm_serial_putc_nolock() ============================
//
// Write a single character to a serial device in a non-locked mode.
// This function is reentrant, and can be safely called even while the normal
// vmm_serial_putc() runs.  However, it is not optimized for performance and
// should only be used when necessary, e.g., from an exception handler.

char                                     // Ret: Character that was sent
vmm_serial_putc_nolock(void *h_device,   // In:  Handle of the device
                       char  c)          // In:  Character to send
{
    VMM_SERIAL_DEVICE *p_device;
    UART_LSR           lsr;   // Line Status Register image
    BOOLEAN            is_ready;
                              // The Tx FIFO is empty and hw handshake is "go"
    UINT32             num_wait_for_tx_ready;


    p_device = h_device;

    VMM_ASSERT(p_device->is_initialized);

    if (p_device->in_puts)
        p_device->num_puts_interrupted_by_putc_nolock++;

    // Another instance of the vmm_serial_putc*() functions can be running in
    // parallel (e.g., on another h/w thread).  We rely on the Tx FIFO to
    // be deed enough absorb the writes (and hope for the best...).  Thus, we
    // first loop until the Tx FIFO is empty and h/w handshake is OK
    // (if applicable)

    num_wait_for_tx_ready = 0;
    do
    {
        lsr.data = hw_read_port_8(p_device->io_base + UART_REGISTER_LSR);

        is_ready = (lsr.bits.THRE == 1) && is_hw_tx_handshake_go(p_device);

        if (! is_ready)
        {
            hw_stall_using_tsc(serial_tx_stall_usec);
            num_wait_for_tx_ready++;
        }
    } while (! is_ready);

    update_max_and_avg(&p_device->wait_for_tx_fifo_empty_max,
                       &p_device->wait_for_tx_fifo_empty_avg,
                       num_wait_for_tx_ready);
    update_max_and_avg(&p_device->wait_for_tx_ready_max,
                       &p_device->wait_for_tx_ready_avg,
                       num_wait_for_tx_ready);

    // Now write the output character

    hw_write_port_8(p_device->io_base + UART_REGISTER_THR, c);

    // Update the statistics

    p_device->num_tx_chars_nolock++;

    // Loop again until the Tx FIFO is empty and h/w handshake is OK
    // (if applicable).  This is done so normal vmm_serial_putc() that we may
    // have interrupted can safely resume.

    num_wait_for_tx_ready = 0;
    do
    {
        lsr.data = hw_read_port_8(p_device->io_base + UART_REGISTER_LSR);

        is_ready = is_hw_tx_handshake_go(p_device) && (lsr.bits.THRE == 1);

        if (! is_ready)
        {
            hw_stall_using_tsc(serial_tx_stall_usec);
            num_wait_for_tx_ready++;
        }
    } while (! is_ready);

    update_max_and_avg(&p_device->wait_for_tx_fifo_empty_max,
                       &p_device->wait_for_tx_fifo_empty_avg,
                       num_wait_for_tx_ready);
    update_max_and_avg(&p_device->wait_for_tx_ready_max,
                       &p_device->wait_for_tx_ready_avg,
                       num_wait_for_tx_ready);

    // Note that we do NOT update chars_in_tx_fifo to be 0.  This allows
    // parallel putc's that will be absorbed by the FIFO.

    return c;
}


//=========================== vmm_serial_putc() ===============================
//
// Write a single character to a serial device.
// This function is not reentrant, and is for use in the normal case, where the
// serial device has been previously locked.  It may be interrupted by
// vmm_serial_putc_nolock().  The function attempts to use the full depth of
// the UART's transmit FIFO to avoid busy loops.

char                              // Ret: Character that was sent
vmm_serial_putc(void *h_device,   // In:  Handle of the device
                char  c)          // In:  Character to send
{
    VMM_SERIAL_DEVICE *p_device;
    UART_LSR           lsr;   // Line Status Register image
    BOOLEAN            is_ready;
                              // The Tx FIFO is not full and hw handshake is "go"
    BOOLEAN            locked_out = FALSE;
                              // Indicate that the function was locked out at
                              // least once by puts_lock
    UINT32             num_wait_for_tx_ready;
    UINT32             num_wait_for_tx_fifo_empty;


    p_device = h_device;

    VMM_ASSERT(p_device->is_initialized);

    // Loop until there's room in the Tx FIFO, h/w handshake is OK
    // (if applicable), and there is no lock by vmm_serial_puts_nolock().

    num_wait_for_tx_ready = 0;
    num_wait_for_tx_fifo_empty = 0;

    do
    {
        lsr.data = hw_read_port_8(p_device->io_base + UART_REGISTER_LSR);
        if (lsr.bits.THRE == 1)        // The Tx FIFO is empty
            p_device->chars_in_tx_fifo = 0;

        is_ready = is_hw_tx_handshake_go(p_device);

        if (is_ready)
        {
            if (p_device->chars_in_tx_fifo >= p_device->hw_fifo_size)
            {
                is_ready = FALSE;
                num_wait_for_tx_fifo_empty++;
            }
        }

        if (is_ready && p_device->puts_lock)
        {
            // There's an on going string print by vmm_serial_puts_nolock()

            is_ready = FALSE;
            locked_out = TRUE;
        }

        if (! is_ready)
        {
            hw_stall_using_tsc(serial_tx_stall_usec);
            num_wait_for_tx_ready++;
        }
    } while (! is_ready);

    update_max_and_avg(&p_device->wait_for_tx_ready_max,
                       &p_device->wait_for_tx_ready_avg,
                       num_wait_for_tx_ready);
    update_max_and_avg(&p_device->wait_for_tx_fifo_empty_max,
                       &p_device->wait_for_tx_fifo_empty_avg,
                       num_wait_for_tx_fifo_empty);

    // Now write the output character

    hw_write_port_8(p_device->io_base + UART_REGISTER_THR, c);

    p_device->chars_in_tx_fifo++;

    // Update the statistics

    p_device->num_tx_chars_lock++;
    if (locked_out)
        p_device->num_putc_blocked_by_puts_nolock++;

    return c;
}


//======================= vmm_serial_puts_nolock() ============================
//
// Write a string to a serial device in a non-locked mode.
// This function is reentrant, and can be safely called even while the normal
// vmm_serial_putc() runs.  However, it should be used only when necessary,
// e.g. from an exception handler.
int                                            // Ret: 0 if failed
vmm_serial_puts_nolock(void       *h_device,   // In:  Handle of the device
                       const char  string[])   // In:  String to send

{
    VMM_SERIAL_DEVICE *p_device;
    UINT32             i;


    p_device = h_device;

    p_device->puts_lock = TRUE;   // Block the normal putc()
                                  // Not reliable in case this function is
                                  // called by two h/w threads in parallel, but
                                  // the impact is not fatal

    if (p_device->in_puts)
        p_device->num_puts_interrupted_by_puts_nolock++;

    for (i = 0; string[i] != 0; i++)
        vmm_serial_putc_nolock(h_device, string[i]);

    p_device->puts_lock = FALSE;   // Unblock the normal putc()

    return 1;   // return any nonnegative value
}

//=========================== vmm_serial_puts() ===============================
//
// Write a string to a serial device
// This function is not reentrant, and is for use in the normal case, where the
// serial device has been previously locked.  It may be interrupted by
// vmm_serial_put*_nolock().

int                                     // Ret: 0 if failed
vmm_serial_puts(void       *h_device,   // In:  Handle of the device
                const char  string[])   // In:  String to send

{
    VMM_SERIAL_DEVICE *p_device;
    UINT32 i;


    p_device = h_device;

    for (i = 0; string[i] != 0; i++)
    {
        vmm_serial_putc(h_device, string[i]);
        p_device->in_puts = TRUE;
    }

    p_device->in_puts = FALSE;

    return 1;   // return any nonnegative value
}

//=========================== vmm_serial_getc() ===============================
//
// Poll the serial device and read a single character if ready.
// This function is not reentrant.  Calling it while it runs in another thread
// may result in a junk character returned, but the s/w will not crash.

char                              // Ret: Character read from the device, 0 if
                                  //      none.
vmm_serial_getc(void *h_device)   // In:  Handle of the device

{
    VMM_SERIAL_DEVICE *p_device;
    UART_LSR           lsr;
    char               c;


    p_device = h_device;

    VMM_ASSERT(p_device->is_initialized);

    lsr.data = hw_read_port_8(p_device->io_base + UART_REGISTER_LSR);
    if (lsr.bits.DR)  // Rx not empty
    {
        c = hw_read_port_8(p_device->io_base + UART_REGISTER_RBR);
        p_device->num_rx_chars++;
    }

    else
        c = 0;

    return c;
}

//======================== vmm_serial_cli_init() ==============================
//
// Initialize CLI command(s) for serial ports

void
vmm_serial_cli_init(void)

{
#ifdef DEBUG
    CLI_AddCommand(cli_display_serial_info,
                   "debug serial info",
                   "Print serial ports information",
                   "",
                   CLI_ACCESS_LEVEL_SYSTEM);
#endif
}

