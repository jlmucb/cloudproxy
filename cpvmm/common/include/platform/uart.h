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

#ifndef _UART_H_
#define _UART_H_

//=============================================================================
//
// UART (Universal Asynchronous Receiver Transmitter) Serial Controller
//
// Hardware Definitions File
//
//=============================================================================

// UART Programming Interface Type (Same as the PCI definition)

typedef enum
{
    UART_PROG_IF_GENERIC = 0,
    UART_PROG_IF_16450   = 1,
    UART_PROG_IF_16550   = 2,   // This is the default
    UART_PROG_IF_16650   = 3,
    UART_PROG_IF_16750   = 4,
    UART_PROG_IF_16850   = 5,
    UART_PROG_IF_16950   = 6,
    UART_PROG_IF_DEFAULT = 2
} UART_PROG_IF_TYPE;

// Serial Port Handshake Mode

typedef enum
{
    UART_HANDSHAKE_NONE     = 0,   // No handshake
    UART_HANDSHAKE_HW       = 1,   // RS-232 signals CTS/RTS and DTR/DSR
    UART_HANDSHAKE_XON_XOFF = 2,   // XON (ctrl-S) and XOFF (ctrl-Q)
    UART_HANDSHAKE_AUTO     = 3,   // Handshake mode is automatically detected
    UART_HANDSHAKE_DEFAULT  = 3
} UART_HANDSHAKE_MODE;

// (24000000/13)MHz input clock

#define UART_INPUT_CLOCK 1843200


// 115200 baud with rounding errors

#define UART_MAX_BAUD_RATE           115400
#define UART_MIN_BAUD_RATE           50

#define UART_MAX_RECEIVE_FIFO_DEPTH  16
#define UART_MIN_TIMEOUT             1         // 1 uS
#define UART_MAX_TIMEOUT             100000000 // 100 seconds

// UART Registers

#define UART_REGISTER_THR 0   // WO   Transmit Holding Register
#define UART_REGISTER_RBR 0   // RO   Receive Buffer Register
#define UART_REGISTER_DLL 0   // R/W  Divisor Latch LSB
#define UART_REGISTER_DLM 1   // R/W  Divisor Latch MSB
#define UART_REGISTER_IER 1   // R/W  Interrupt Enable Register
#define UART_REGISTER_IIR 2   // RO   Interrupt Identification Register
#define UART_REGISTER_FCR 2   // WO   FIFO Cotrol Register
#define UART_REGISTER_LCR 3   // R/W  Line Control Register
#define UART_REGISTER_MCR 4   // R/W  Modem Control Register
#define UART_REGISTER_LSR 5   // R/W  Line Status Register
#define UART_REGISTER_MSR 6   // R/W  Modem Status Register
#define UART_REGISTER_SCR 7   // R/W  Scratch Pad Register

#pragma pack(1)

//  Name:   UART_IER_BITS
//  Purpose:  Define each bit in Interrupt Enable Register
//  Context:
//  Fields:
//     RAVIE  Bit0: Receiver Data Available Interrupt Enable
//     THEIE  Bit1: Transmistter Holding Register Empty Interrupt Enable
//     RIE      Bit2: Receiver Interrupt Enable
//     MIE      Bit3: Modem Interrupt Enable
//     Reserved Bit4-Bit7: Reserved

typedef struct
{
    unsigned int RAVIE    : 1;
    unsigned int THEIE    : 1;
    unsigned int RIE      : 1;
    unsigned int MIE      : 1;
    unsigned int Reserved : 4;
} PACKED UART_IER_BITS;


//  Name:   UART_IER
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_IER_BITS:  Bits of the IER
//      Data    UINT8: the value of the IER

typedef union
{
    UART_IER_BITS  bits;
    UINT8          data;
} UART_IER;

//  Name:   UART_IIR_BITS
//  Purpose:  Define each bit in Interrupt Identification Register
//  Context:
//  Fields:
//      IPS    Bit0: Interrupt Pending Status
//      IIB    Bit1-Bit3: Interrupt ID Bits
//      Reserved Bit4-Bit5: Reserved
//      FIFOES   Bit6-Bit7: FIFO Mode Enable Status

typedef struct
{
    unsigned int IPS      : 1;
    unsigned int IIB      : 3;
    unsigned int Reserved : 2;
    unsigned int FIFOES   : 2;
} PACKED UART_IIR_BITS;

//  Name:   UART_IIR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_IIR_BITS:  Bits of the IIR
//      Data    UINT8: the value of the IIR

typedef union
{
    UART_IIR_BITS  bits;
    UINT8          data;
} UART_IIR;

//  Name:   UART_FCR_BITS
//  Purpose:  Define each bit in FIFO Control Register
//  Context:
//  Fields:
//      TRFIFOE    Bit0: Transmit and Receive FIFO Enable
//      RESETRF    Bit1: Reset Reciever FIFO
//      RESETTF    Bit2: Reset Transmistter FIFO
//      DMS        Bit3: DMA Mode Select
//      Reserved   Bit4-Bit5: Reserved
//      RTB        Bit6-Bit7: Receive Trigger Bits

typedef struct
{
    unsigned int TRFIFOE  : 1;
    unsigned int RESETRF  : 1;
    unsigned int RESETTF  : 1;
    unsigned int DMS      : 1;
    unsigned int Reserved : 2;
    unsigned int RTB      : 2;
} PACKED UART_FCR_BITS;

//  Name:   UART_FCR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_FCR_BITS:  Bits of the FCR
//      Data    UINT8: the value of the FCR

typedef union
{
    UART_FCR_BITS  bits;
    UINT8          data;
} UART_FCR;

//  Name:   UART_LCR_BITS
//  Purpose:  Define each bit in Line Control Register
//  Context:
//  Fields:
//      SERIALDB  Bit0-Bit1: Number of Serial Data Bits
//      STOPB   Bit2: Number of Stop Bits
//      PAREN   Bit3: Parity Enable
//      EVENPAR   Bit4: Even Parity Select
//      STICPAR   Bit5: Sticky Parity
//      BRCON   Bit6: Break Control
//      DLAB    Bit7: Divisor Latch Access Bit

typedef struct
{
    unsigned int SERIALDB : 2;
    unsigned int STOPB    : 1;
    unsigned int PAREN    : 1;
    unsigned int EVENPAR  : 1;
    unsigned int STICPAR  : 1;
    unsigned int BRCON    : 1;
    unsigned int DLAB     : 1;
} PACKED UART_LCR_BITS;

//  Name:   UART_LCR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_LCR_BITS:  Bits of the LCR
//      Data    UINT8: the value of the LCR

typedef union
{
    UART_LCR_BITS  bits;
    UINT8          data;
} UART_LCR;

//  Name:   UART_MCR_BITS
//  Purpose:  Define each bit in Modem Control Register
//  Context:
//  Fields:
//      DTRC     Bit0: Data Terminal Ready Control
//      RTS      Bit1: Request To Send Control
//      OUT1     Bit2: Output1
//      OUT2     Bit3: Output2, used to disable interrupt
//      LME;     Bit4: Loopback Mode Enable
//      Reserved Bit5-Bit7: Reserved

typedef struct
{
    unsigned int DTRC     : 1;
    unsigned int RTS      : 1;
    unsigned int OUT1     : 1;
    unsigned int OUT2     : 1;
    unsigned int LME      : 1;
    unsigned int Reserved : 3;
} PACKED UART_MCR_BITS;

//  Name:   UART_MCR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_MCR_BITS:  Bits of the MCR
//      Data    UINT8: the value of the MCR

typedef union
{
    UART_MCR_BITS  bits;
    UINT8          data;
} UART_MCR;

//  Name:   UART_LSR_BITS
//  Purpose:  Define each bit in Line Status Register
//  Context:
//  Fields:
//      DR    Bit0: Receiver Data Ready Status
//      OE    Bit1: Overrun Error Status
//      PE    Bit2: Parity Error Status
//      FE    Bit3: Framing Error Status
//      BI    Bit4: Break Interrupt Status
//      THRE  Bit5: Transmistter Holding Register Status
//      TEMT  Bit6: Transmitter Empty Status
//      FIFOE Bit7: FIFO Error Status

typedef struct
{
    unsigned int DR    : 1;
    unsigned int OE    : 1;
    unsigned int PE    : 1;
    unsigned int FE    : 1;
    unsigned int BI    : 1;
    unsigned int THRE  : 1;
    unsigned int TEMT  : 1;
    unsigned int FIFOE : 1;
} PACKED UART_LSR_BITS;

//  Name:   UART_LSR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_LSR_BITS:  Bits of the LSR
//      Data    UINT8: the value of the LSR

typedef union
{
    UART_LSR_BITS  bits;
    UINT8          data;
} UART_LSR;

//  Name:   UART_MSR_BITS
//  Purpose:  Define each bit in Modem Status Register
//  Context:
//  Fields:
//      DeltaCTS      Bit0: Delta Clear To Send Status
//      DeltaDSR        Bit1: Delta Data Set Ready Status
//      TrailingEdgeRI  Bit2: Trailing Edge of Ring Indicator Status
//      DeltaDCD        Bit3: Delta Data Carrier Detect Status
//      CTS             Bit4: Clear To Send Status
//      DSR             Bit5: Data Set Ready Status
//      RI              Bit6: Ring Indicator Status
//      DCD             Bit7: Data Carrier Detect Status

typedef struct
{
    unsigned int DeltaCTS       : 1;
    unsigned int DeltaDSR       : 1;
    unsigned int TrailingEdgeRI : 1;
    unsigned int DeltaDCD       : 1;
    unsigned int CTS            : 1;
    unsigned int DSR            : 1;
    unsigned int RI             : 1;
    unsigned int DCD            : 1;
} PACKED UART_MSR_BITS;

//  Name:   UART_MSR
//  Purpose:
//  Context:
//  Fields:
//      Bits    UART_MSR_BITS:  Bits of the MSR
//      Data    UINT8: the value of the MSR

typedef union
{
    UART_MSR_BITS  bits;
    UINT8          data;
} UART_MSR;

#pragma pack()

#endif
