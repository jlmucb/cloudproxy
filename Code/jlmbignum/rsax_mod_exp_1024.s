; Copyright (c) 2012, Intel Corporation 
; 
; All rights reserved. 
; 
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are
; met: 
; 
; * Redistributions of source code must retain the above copyright
;   notice, this list of conditions and the following disclaimer.  
; 
; * Redistributions in binary form must reproduce the above copyright
;   notice, this list of conditions and the following disclaimer in the
;   documentation and/or other materials provided with the
;   distribution. 
; 
; * Neither the name of the Intel Corporation nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission. 
; 
; 
; THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
; PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

; Authors:
;       Erdinc Ozturk
;       James Guilford
;       Vinodh Gopal
; constant-time modular exponentiation
; mod-exp 1024 with mul, add, adc instructions
; single loop windowing code
; fixed windowing with window size of 5 bits
; YASM syntax, x64 instructions
; 
; void rsax_mod_exp_1024(
;       u64 *result, // 1024 bits, 16 qwords
;       u64 *g,      // 1024 bits, 16 qwords
;       u64 *exp,    // 1024 bits, 16 qwords
;       MOD_EXP_1024_DATA *data);
;
; struct MOD_EXP_1024_DATA {
;       u64 R[16];   // 2^1024 % m
;       u64 R2[16];  // 2^2048 % m
;       u64 M[16];   // m
;       u64 m_1[1];  // (-1/m) % 2^64
;        
; Montgomery Reduction algorithm is used with b = 2^64, 
;    n = 16, R = 2^1024, m' = -m^(-1) mod 2^64
; Reference: Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone. 
;    Handbook of Applied Cryptography. October 1996.
;
;    sample command line for WINDOWS*:
;        yasm -Xvc -f x64 -rnasm -pnasm -o objfile -l "" -g cv8
; No definition is required for LINUX.
; 

%ifdef WIN_ABI
        ; WINDOWS* ABI
        %xdefine arg1 rcx
        %xdefine arg2 rdx
        %xdefine arg3 r8
        %xdefine arg4 r9
        extern  __chkstk
%else
        ; LINUX* ABI
        %xdefine arg1 rdi
        %xdefine arg2 rsi
        %xdefine arg3 rdx
        %xdefine arg4 rcx
%endif

; Define d and w variants for registers
; used in the swizzle and unswizzle macros
%define raxd    eax
%define raxw    ax
%define raxb    al

%define rbxd    ebx
%define rbxw    bx
%define rbxb    bl

%define rcxd    ecx
%define rcxw    cx
%define rcxb    cl

%define rdxd    edx
%define rdxw    dx
%define rdxb    dl

%define rsid    esi
%define rsiw    si

%define rdid    edi
%define rdiw    di

%define rbpd    ebp
%define rbpw    bp


;; Define utility macros
; macro used to replace op reg, mem instructions
; Execute reg-mem opcode using explicit load

%macro op_reg_mem 4
%define %%OPC   %1      ; instruction
%define %%DST   %2      ; destination (register)
%define %%SRC1  %3      ; source 1 (memory)
%define %%TMP   %4      ; temp (register)
        mov     %%TMP, %%SRC1
        %%OPC   %%DST, %%TMP
%endmacro

; macro used to implement "op mem, mem" instructions
; macro accepts 1 destination and 2 src inputs, in a nondestructive manner
; macro op_mem_mem OPCODE, MEM_DST, MEM_SRC1, MEM_SRC2, TMP
%macro op_mem_mem 5
%define %%OPC   %1
%define %%DST   %2      ; destination (memory)
%define %%SRC1  %3      ; source 1 (memory)
%define %%SRC2  %4      ; source 2 (memory)
%define %%TMP1  %5      ; temp (register)
        mov     %%TMP1, %%SRC1
        %%OPC   %%TMP1, %%SRC2
        mov     %%DST, %%TMP1
%endmacro


; macro used to implement "op reg, mem" instructions followed by a store 
; macro op_mem_reg_mem OPCODE, MEM_DST, REG_SRC1, MEM_SRC2
%macro op_mem_reg_mem 5
%define %%OPC   %1
%define %%DST   %2      ; destination (memory)
%define %%SRC1  %3      ; source 1 (reg)
%define %%SRC2  %4      ; source 2 (memory)
%define %%TMP1  %5
        %%OPC   %%SRC1, %%SRC2
        mov     %%DST, %%SRC1
%endmacro


; Define multiplication macros
; Diagonal Macro
; 64x512  bit multiplication accumulated with 512-bit intermediate result
; 1 QW x 8 QW
; Source 1: %%OP register
; Source 2: %%SRC2
; Intermediate result: Registers %%X7:%%X0
; if %%if_store is not '-', result stored in %%X0, %%X7:%%X1, %%DST
; if %%if_store is '-', result stored in %%X0, %%X7:%%X1, lowest QW is discarded
; clobbers rax and rdx

%macro  MULSTEP_512     13
%define %%X7    %1
%define %%X6    %2
%define %%X5    %3
%define %%X4    %4
%define %%X3    %5
%define %%X2    %6
%define %%X1    %7
%define %%X0    %8
%define %%DST   %9
%define %%SRC2  %10
%define %%OP    %11
%define %%TMP   %12
%define %%if_store   %13

        mov     rax, [%%SRC2+8*0]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*1]
        add     %%X0, rax
        adc     rdx, 0
        mov     %%TMP, rdx

%ifnidn %%if_store, -
        mov     %%DST, %%X0
%endif

        mov     rax, [%%SRC2+8*1]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*0]
        mov     %%X0, rdx
        add     %%X1, rax
        adc     %%X0, 0
        add     %%X1, %%TMP
        adc     %%X0, 0

        mov     rax, [%%SRC2+8*2]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*2]
        mov     %%TMP, rdx
        add     %%X2, rax
        adc     %%TMP, 0
        add     %%X2, %%X0
        adc     %%TMP, 0

        mov     rax, [%%SRC2+8*3]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*3]
        mov     %%X0, rdx
        add     %%X3, rax
        adc     %%X0, 0
        add     %%X3, %%TMP
        adc     %%X0, 0
        
        mov     rax, [%%SRC2+8*4]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*4]
        mov     %%TMP, rdx
        add     %%X4, rax
        adc     %%TMP, 0
        add     %%X4, %%X0
        adc     %%TMP, 0

        mov     rax, [%%SRC2+8*5]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*5]
        mov     %%X0, rdx
        add     %%X5, rax
        adc     %%X0, 0
        add     %%X5, %%TMP
        adc     %%X0, 0

        mov     rax, [%%SRC2+8*6]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*6]
        mov     %%TMP, rdx
        add     %%X6, rax
        adc     %%TMP, 0
        add     %%X6, %%X0
        adc     %%TMP, 0
        

        mov     rax, [%%SRC2+8*7]
        mul     %%OP                    ; rdx:rax = %OP * [%%SRC2+8*7]
        mov     %%X0, rdx
        add     %%X7, rax
        adc     %%X0, 0
        add     %%X7, %%TMP
        adc     %%X0, 0

%endmacro


; MUL_512x512: Do a 512x512 bit mulitplication
; %%X7:%%X0: High half of destination (512 bits, 8 qwords)
; pDst:      Low half of destination (512 bits, 8 qwords)
; pA:        Multiplicand (512 bits, 8 qwords)
; pB:        Multiplicand (512 bits, 8 qwords)
; clobbers rax, rdx, rbp
;
; If first_mul is '-', then the results of the multiplication are 
;     stored in the destination
; If first_mul is not '-', then the results are added to the destination.
%macro  MUL_512x512 14
%define %%pDst  %1
%define %%pA    %2
%define %%pB    %3
%define %%X7    %4
%define %%X6    %5
%define %%X5    %6
%define %%X4    %7
%define %%X3    %8
%define %%X2    %9
%define %%X1    %10
%define %%X0    %11     
%define %%OP    %12
%define %%TMP   %13
%define %%first_mul     %14     ; this is needed for constructing a 1024x1024 multiplication using this macro.

%ifnidn %%first_mul, -
        mov     %%OP, [%%pA+8*0]

        mov     rax, [%%pB+8*0]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*0]
        mov     [%%pDst+8*0], rax
        mov     %%X1, rdx

        mov     rax, [%%pB+8*1]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*1]
        add     %%X1, rax
        adc     rdx, 0
        mov     %%X2, rdx

        mov     rax, [%%pB+8*2]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*2]
        add     %%X2, rax
        adc     rdx, 0
        mov     %%X3, rdx

        mov     rax, [%%pB+8*3]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*3]
        add     %%X3, rax
        adc     rdx, 0
        mov     %%X4, rdx

        mov     rax, [%%pB+8*4]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*4]
        add     %%X4, rax
        adc     rdx, 0
        mov     %%X5, rdx

        mov     rax, [%%pB+8*5]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*5]
        add     %%X5, rax
        adc     rdx, 0
        mov     %%X6, rdx

        mov     rax, [%%pB+8*6]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*6]
        add     %%X6, rax
        adc     rdx, 0
        mov     %%X7, rdx

        mov     rax, [%%pB+8*7]
        mul     %%OP                    ; rdx:rax = %OP * [%%pB+8*7]
        add     %%X7, rax
        adc     rdx, 0
        mov     %%X0, rdx
%else
        mov     rbp, [%%pA+8*0]
        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*0], %%pB, %%OP, %%TMP, store
%endif
        mov     rbp, [%%pA+8*1]
        MULSTEP_512     %%X0, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, [%%pDst+8*1], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*2]                                         
        MULSTEP_512     %%X1, %%X0, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, [%%pDst+8*2], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*3]                                         
        MULSTEP_512     %%X2, %%X1, %%X0, %%X7, %%X6, %%X5, %%X4, %%X3, [%%pDst+8*3], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*4]                                         
        MULSTEP_512     %%X3, %%X2, %%X1, %%X0, %%X7, %%X6, %%X5, %%X4, [%%pDst+8*4], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*5]                                         
        MULSTEP_512     %%X4, %%X3, %%X2, %%X1, %%X0, %%X7, %%X6, %%X5, [%%pDst+8*5], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*6]                                         
        MULSTEP_512     %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%X7, %%X6, [%%pDst+8*6], %%pB, %%OP, %%TMP, store
        mov     rbp, [%%pA+8*7]                                         
        MULSTEP_512     %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%X7, [%%pDst+8*7], %%pB, %%OP, %%TMP, store

%endmacro


; MUL_1024_1024: Do a 1024x1024 bit multiplication
; pDst: Destination  (2048 bits, 32 qwords)
; pA:   Multiplicand (1024 bits, 16 qwords)
; pB:   Multiplicand (1024 bits, 16 qwords)
; pDst, pA, pB are not clobbered
; T1, T2, %%X7: %%X0 are clobbered
; rax and rdx are clobbered
%macro  MUL_1024_1024 13
%define %%pDst  %1
%define %%pA    %2
%define %%pB    %3
%define %%X7    %4
%define %%X6    %5
%define %%X5    %6
%define %%X4    %7
%define %%X3    %8
%define %%X2    %9
%define %%X1    %10
%define %%X0    %11
%define %%T1    %12
%define %%T2    %13
        
        MUL_512x512     %%pDst, %%pA, %%pB, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, first_mul

        MUL_512x512     %%pDst+8*8, %%pA, %%pB+8*8, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
        mov     [%%pDst+8*16],%%X0
        mov     [%%pDst+8*17],%%X1
        mov     [%%pDst+8*18],%%X2
        mov     [%%pDst+8*19],%%X3
        mov     [%%pDst+8*20],%%X4
        mov     [%%pDst+8*21],%%X5
        mov     [%%pDst+8*22],%%X6
        mov     [%%pDst+8*23],%%X7
        
        mov     %%X0, [%%pDst+8*8]
        mov     %%X1, [%%pDst+8*9]
        mov     %%X2, [%%pDst+8*10]
        mov     %%X3, [%%pDst+8*11]
        mov     %%X4, [%%pDst+8*12]
        mov     %%X5, [%%pDst+8*13]
        mov     %%X6, [%%pDst+8*14]
        mov     %%X7, [%%pDst+8*15]

        MUL_512x512     %%pDst+8*8, %%pA+8*8, %%pB, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
        xor     %%T1, %%T1

        add     %%X0, [%%pDst+8*16]
        adc     %%X1, [%%pDst+8*17]
        adc     %%X2, [%%pDst+8*18]
        adc     %%X3, [%%pDst+8*19]
        adc     %%X4, [%%pDst+8*20]
        adc     %%X5, [%%pDst+8*21]
        adc     %%X6, [%%pDst+8*22]
        adc     %%X7, [%%pDst+8*23]
        adc     %%T1, 0
        push    %%T1
        
        MUL_512x512     %%pDst+8*16, %%pA+8*8, %%pB+8*8, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
        
        pop     %%T1
        add     %%X0, %%T1
        adc     %%X1, 0
        adc     %%X2, 0
        adc     %%X3, 0
        adc     %%X4, 0
        adc     %%X5, 0
        adc     %%X6, 0
        adc     %%X7, 0
        
        mov     [%%pDst+8*24],%%X0
        mov     [%%pDst+8*25],%%X1
        mov     [%%pDst+8*26],%%X2
        mov     [%%pDst+8*27],%%X3
        mov     [%%pDst+8*28],%%X4
        mov     [%%pDst+8*29],%%X5
        mov     [%%pDst+8*30],%%X6
        mov     [%%pDst+8*31],%%X7
%endmacro


; Define squaring macros

; MULADD  acc, a1, src, mem
; acc:a1 = src * mem + a1 + acc
; clobbers rax, rdx
%macro  MULADD  4
%define %%acc %1
%define %%a1  %2
%define %%src %3
%define %%mem %4
        mov     rax, %%mem
        mul     %%src
        add     %%a1, rax
        adc     rdx, 0
        add     %%a1, %%acc
        adc     rdx, 0
        mov     %%acc, rdx
%endmacro


; MULADD1 acc, a1, src, mem
; acc:a1 = src * mem + a1
; clobbers rax, rdx
%macro  MULADD1 4
%define %%acc %1
%define %%a1  %2
%define %%src %3
%define %%mem %4
        mov     rax, %%mem
        mul     %%src
        add     %%a1, rax
        adc     rdx, 0
        mov     %%acc, rdx
%endmacro


; MULADD2  a3, a2, a1, src, mem
; a3:a2:a1 = src * mem + a1 + a2:0
; clobbers rax, rdx
%macro  MULADD2  5
%define %%a3  %1
%define %%a2  %2
%define %%a1  %3
%define %%src %4
%define %%mem %5
        mov     rax, %%mem
        mul     %%src
        add     %%a1, rax
        adc     rdx, 0
        add     %%a2, rdx
        adc     %%a3, 0
%endmacro


; Macro used in "finalizing" square. It is used to add twice the off-diagonal
; terms to the squares of the diagonal terms.
; x7:x0 are the doubled off-diagonal terms
; in and out chain finalizes together.
; sqr is part of one of the on-diagonal squares.
; 
; pA          4         3         2         1         0
; pDst     9    8    7    6    5    4    3    2    1    0
; col:     9    8 |  7    6 |  5    4 |  3    2 |  1    0
;                                                 in
;             sqr
;              x7   x6   x5   x4   x3   x2   x1   x0
;        out
;
; out contain carry out, x7...x0 are doubled, so x0 is even
; sqr has low half of pA[4] squared
;
%macro  FINALIZE 13
%define %%pA   %1
%define %%pDst %2
%define %%in   %3
%define %%out  %4
%define %%sqr  %5
%define %%x0   %6
%define %%x1   %7 
%define %%x2   %8
%define %%x3   %9
%define %%x4   %10
%define %%x5   %11
%define %%x6   %12
%define %%x7   %13

        mov     rax, [%%pA + 8*1]
        mul     rax

        add     %%x0, %%in
        adc     %%x1, rax
        adc     rdx, 0

        mov     %%in, rdx
        mov     [%%pDst + 8*1], %%x0
        mov     [%%pDst + 8*2], %%x1

        ;; ----------------

        mov     rax, [%%pA + 8*2]
        mul     rax

        add     %%x2, %%in
        adc     %%x3, rax
        adc     rdx, 0

        mov     %%in, rdx

        mov     [%%pDst + 8*3], %%x2
        mov     [%%pDst + 8*4], %%x3

        ;; ----------------

        mov     rax, [%%pA + 8*3]
        mul     rax

        add     %%x4, %%in
        adc     %%x5, rax
        adc     rdx, 0

        mov     %%in, rdx

        mov     [%%pDst + 8*5], %%x4
        mov     [%%pDst + 8*6], %%x5

        ;; ----------------

        xor     %%out, %%out
        add     %%x6, %%in
        adc     %%x7, %%sqr
        adc     %%out, 0

        mov     [%%pDst + 8*7], %%x6
        mov     [%%pDst + 8*8], %%x7
%endmacro

; --------------------------------------------------

; SQR_1024: Square a 1024-bit number
; rax, rdx are clobbered
%macro SQR_1024 14
%define %%pDst  %1
%define %%pA    %2
%define %%A     %3
%define %%t0    %4
%define %%x9    %5
%define %%x8    %6
%define %%x7    %7
%define %%x6    %8
%define %%x5    %9
%define %%x4    %10
%define %%x3    %11
%define %%x2    %12
%define %%x1    %13
%define %%x0    %14

        ;; ------------------
        ;; pass: 00 01...00 10
        ;; ------------------

        mov     %%A, [%%pA + 8*0]
        mov     rax, [%%pA + 8*1]
        mul     %%A

        mov     [%%pDst + 8*1], rax
        mov     %%x9, rdx

        MULADD1 %%x0, %%x9, %%A, [%%pA + 8*2]
        MULADD1 %%x1, %%x0, %%A, [%%pA + 8*3]
        MULADD1 %%x2, %%x1, %%A, [%%pA + 8*4]
        MULADD1 %%x3, %%x2, %%A, [%%pA + 8*5]
        MULADD1 %%x4, %%x3, %%A, [%%pA + 8*6]
        MULADD1 %%x5, %%x4, %%A, [%%pA + 8*7]
        MULADD1 %%x6, %%x5, %%A, [%%pA + 8*8]
        MULADD1 %%x7, %%x6, %%A, [%%pA + 8*9]
        MULADD1 %%x8, %%x7, %%A, [%%pA + 8*10]

        mov     %%A, [%%pA + 8*1]
        mov     [%%pDst + 8*2], %%x9
        xor     %%x9, %%x9

        ;; ------------------
        ;; pass: 01 02...01 09
        ;; ------------------

        MULADD1 %%t0, %%x0, %%A, [%%pA + 8*2]
        mov     [%%pDst + 8*3], %%x0
        MULADD  %%t0, %%x1, %%A, [%%pA + 8*3]
        mov     [%%pDst + 8*4], %%x1
        MULADD  %%t0, %%x2, %%A, [%%pA + 8*4]
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*5]
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*6]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*7]
        MULADD  %%t0, %%x6, %%A, [%%pA + 8*8]
        MULADD  %%t0, %%x7, %%A, [%%pA + 8*9]

        mov     %%A, [%%pA + 8*2]
        add     %%x8, %%t0
        adc     %%x9, 0

        ;; ------------------
        ;; pass: 02 03...02 08
        ;; ------------------

        MULADD1 %%t0, %%x2, %%A, [%%pA + 8*3]
        mov     [%%pDst + 8*5], %%x2
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*4]
        mov     [%%pDst + 8*6], %%x3
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*5]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*6]
        MULADD  %%t0, %%x6, %%A, [%%pA + 8*7]
        MULADD  %%t0, %%x7, %%A, [%%pA + 8*8]

        mov     %%A, [%%pA + 8*3]
        add     %%x8, %%t0
        adc     %%x9, 0

        ;; ------------------
        ;; pass: 03 04...03 07
        ;; ------------------

        MULADD1 %%t0, %%x4, %%A, [%%pA + 8*4]
        mov     [%%pDst + 8*7], %%x4
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*5]
        mov     [%%pDst + 8*8], %%x5
        MULADD  %%t0, %%x6, %%A, [%%pA + 8*6]
        MULADD  %%t0, %%x7, %%A, [%%pA + 8*7]

        mov     %%A, [%%pA + 8*4]
        add     %%x8, %%t0
        adc     %%x9, 0

        ;; ------------------
        ;; pass: 04 05...04 06
        ;; ------------------

        MULADD1 %%t0, %%x6, %%A, [%%pA + 8*5]
        mov     [%%pDst + 8*9], %%x6
        MULADD  %%t0, %%x7, %%A, [%%pA + 8*6]
        mov     [%%pDst + 8*10], %%x7

        mov     %%A, [%%pA + 8*0]
        add     %%x8, %%t0
        adc     %%x9, 0

        ;;;;;;;;;;;;;;;;

        ;; ------------------
        ;; pass: 00 11...00 15
        ;; ------------------

        MULADD1 %%x0, %%x8, %%A, [%%pA + 8*11]
        MULADD  %%x0, %%x9, %%A, [%%pA + 8*12]
        MULADD1 %%x1, %%x0, %%A, [%%pA + 8*13]
        MULADD1 %%x2, %%x1, %%A, [%%pA + 8*14]
        MULADD1 %%x3, %%x2, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*1]

        ;; ------------------
        ;; pass: 01 10...01 15
        ;; ------------------

        MULADD1 %%x4, %%x8, %%A, [%%pA + 8*10]
        MULADD  %%x4, %%x9, %%A, [%%pA + 8*11]
        MULADD  %%x4, %%x0, %%A, [%%pA + 8*12]
        MULADD  %%x4, %%x1, %%A, [%%pA + 8*13]
        MULADD  %%x4, %%x2, %%A, [%%pA + 8*14]
        MULADD  %%x4, %%x3, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*2]

        ;; ------------------
        ;; pass: 02 09...02 15
        ;; ------------------

        MULADD1 %%x5, %%x8, %%A, [%%pA + 8*9]
        MULADD  %%x5, %%x9, %%A, [%%pA + 8*10]
        MULADD  %%x5, %%x0, %%A, [%%pA + 8*11]
        MULADD  %%x5, %%x1, %%A, [%%pA + 8*12]
        MULADD  %%x5, %%x2, %%A, [%%pA + 8*13]
        MULADD  %%x5, %%x3, %%A, [%%pA + 8*14]
        MULADD  %%x5, %%x4, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*3]

        ;; ------------------
        ;; pass: 03 08...03 15
        ;; ------------------

        MULADD1 %%x6, %%x8, %%A, [%%pA + 8*8]
        MULADD  %%x6, %%x9, %%A, [%%pA + 8*9]
        MULADD  %%x6, %%x0, %%A, [%%pA + 8*10]
        MULADD  %%x6, %%x1, %%A, [%%pA + 8*11]
        MULADD  %%x6, %%x2, %%A, [%%pA + 8*12]
        MULADD  %%x6, %%x3, %%A, [%%pA + 8*13]
        MULADD  %%x6, %%x4, %%A, [%%pA + 8*14]
        MULADD  %%x6, %%x5, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*4]
        xor     %%x7, %%x7

        ;; ------------------
        ;; pass: 04 07...04 14
        ;; ------------------

        MULADD1 %%t0, %%x8, %%A, [%%pA + 8*7]
        MULADD  %%t0, %%x9, %%A, [%%pA + 8*8]
        MULADD  %%t0, %%x0, %%A, [%%pA + 8*9]
        MULADD  %%t0, %%x1, %%A, [%%pA + 8*10]
        MULADD  %%t0, %%x2, %%A, [%%pA + 8*11]
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*12]
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*13]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*14]

        mov     %%A, [%%pA + 8*5]
        add     %%x6, %%t0
        adc     %%x7, 0

        ;; ------------------
        ;; pass: 05 06...05 13
        ;; ------------------

        MULADD1 %%t0, %%x8, %%A, [%%pA + 8*6]
        MULADD  %%t0, %%x9, %%A, [%%pA + 8*7]
        MULADD  %%t0, %%x0, %%A, [%%pA + 8*8]
        MULADD  %%t0, %%x1, %%A, [%%pA + 8*9]
        MULADD  %%t0, %%x2, %%A, [%%pA + 8*10]
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*11]
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*12]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*13]

        mov     %%A, [%%pA + 8*6]
        add     %%x6, %%t0
        adc     %%x7, 0
        mov     [%%pDst + 8*11], %%x8
        mov     [%%pDst + 8*12], %%x9

        ;; ------------------
        ;; pass: 06 07...06 12
        ;; ------------------

        MULADD1 %%t0, %%x0, %%A, [%%pA + 8*7]
        MULADD  %%t0, %%x1, %%A, [%%pA + 8*8]
        MULADD  %%t0, %%x2, %%A, [%%pA + 8*9]
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*10]
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*11]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*12]

        mov     %%A, [%%pA + 8*7]
        add     %%x6, %%t0
        adc     %%x7, 0
        mov     [%%pDst + 8*13], %%x0
        mov     [%%pDst + 8*14], %%x1

        ;; ------------------
        ;; pass: 07 08...07 11
        ;; ------------------

        MULADD1 %%t0, %%x2, %%A, [%%pA + 8*8]
        MULADD  %%t0, %%x3, %%A, [%%pA + 8*9]
        MULADD  %%t0, %%x4, %%A, [%%pA + 8*10]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*11]

        mov     %%A, [%%pA + 8*8]
        add     %%x6, %%t0
        adc     %%x7, 0
        mov     [%%pDst + 8*15], %%x2
        mov     [%%pDst + 8*16], %%x3

        ;; ------------------
        ;; pass: 08 09...08 10
        ;; ------------------

        MULADD1 %%t0, %%x4, %%A, [%%pA + 8*9]
        MULADD  %%t0, %%x5, %%A, [%%pA + 8*10]

        add     %%x6, %%t0
        adc     %%x7, 0
        mov     [%%pDst + 8*17], %%x4
        mov     [%%pDst + 8*18], %%x5

        ;;;;;;;;;;;;;;;;

        ;; ------------------
        ;; pass: 04 15...04 15
        ;; ------------------

        xor     %%x3, %%x3
        mov     %%A, [%%pA + 8*5]

        mov     rax, [%%pA + 8*15]
        mul     qword [%%pA + 8*4]
        add     %%x6, rax
        adc     rdx, 0
        add     %%x7, rdx
        adc     %%x3, 0

        ;; ------------------
        ;; pass: 05 14...05 15
        ;; ------------------

        MULADD1 %%x8, %%x6, %%A, [%%pA + 8*14]
        MULADD  %%x8, %%x7, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*6]

        ;; ------------------
        ;; pass: 06 13...06 15
        ;; ------------------

        MULADD1 %%x9, %%x6, %%A, [%%pA + 8*13]
        MULADD  %%x9, %%x7, %%A, [%%pA + 8*14]
        MULADD  %%x9, %%x8, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*7]

        ;; ------------------
        ;; pass: 07 12...07 15
        ;; ------------------

        MULADD1 %%x0, %%x6, %%A, [%%pA + 8*12]
        MULADD  %%x0, %%x7, %%A, [%%pA + 8*13]
        MULADD  %%x0, %%x8, %%A, [%%pA + 8*14]
        MULADD  %%x0, %%x9, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*8]

        ;; ------------------
        ;; pass: 08 11...08 15
        ;; ------------------

        MULADD1 %%x1, %%x6, %%A, [%%pA + 8*11]
        MULADD  %%x1, %%x7, %%A, [%%pA + 8*12]
        MULADD  %%x1, %%x8, %%A, [%%pA + 8*13]
        MULADD  %%x1, %%x9, %%A, [%%pA + 8*14]
        MULADD  %%x1, %%x0, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*9]

        ;; ------------------
        ;; pass: 09 10...09 15
        ;; ------------------

        MULADD1 %%x2, %%x6, %%A, [%%pA + 8*10]
        MULADD  %%x2, %%x7, %%A, [%%pA + 8*11]
        MULADD  %%x2, %%x8, %%A, [%%pA + 8*12]
        MULADD  %%x2, %%x9, %%A, [%%pA + 8*13]
        MULADD  %%x2, %%x0, %%A, [%%pA + 8*14]
        MULADD  %%x2, %%x1, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*10]

        mov     [%%pDst + 8*19], %%x6
        mov     [%%pDst + 8*20], %%x7

        ;; ------------------
        ;; pass: 10 11...10 15
        ;; ------------------

        ;; following is MULADD not MULADD1 to pick up %%x3 from above
        MULADD  %%x3, %%x8, %%A, [%%pA + 8*11]
        MULADD  %%x3, %%x9, %%A, [%%pA + 8*12]
        MULADD  %%x3, %%x0, %%A, [%%pA + 8*13]
        MULADD  %%x3, %%x1, %%A, [%%pA + 8*14]
        MULADD  %%x3, %%x2, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*11]

        mov     [%%pDst + 8*21], %%x8
        mov     [%%pDst + 8*22], %%x9

        ;; ------------------
        ;; pass: 11 12...11 15
        ;; ------------------

        MULADD1 %%x4, %%x0, %%A, [%%pA + 8*12]
        MULADD  %%x4, %%x1, %%A, [%%pA + 8*13]
        MULADD  %%x4, %%x2, %%A, [%%pA + 8*14]
        MULADD  %%x4, %%x3, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*12]

        mov     [%%pDst + 8*23], %%x0
        mov     [%%pDst + 8*24], %%x1

        ;; ------------------
        ;; pass: 12 13...12 15
        ;; ------------------

        MULADD1 %%x5, %%x2, %%A, [%%pA + 8*13]
        MULADD  %%x5, %%x3, %%A, [%%pA + 8*14]
        MULADD  %%x5, %%x4, %%A, [%%pA + 8*15]

        mov     %%A, [%%pA + 8*13]

        mov     [%%pDst + 8*25], %%x2
        mov     [%%pDst + 8*26], %%x3

        ;; ------------------
        ;; pass: 13 14...13 15, 14 15
        ;; ------------------

        MULADD1 %%x6, %%x4, %%A, [%%pA + 8*14]
        MULADD  %%x6, %%x5, %%A, [%%pA + 8*15]

        MULADD1 %%x7, %%x6, qword [%%pA + 8*14], [%%pA + 8*15]

        mov     [%%pDst + 8*27], %%x4
        mov     [%%pDst + 8*28], %%x5
        mov     [%%pDst + 8*29], %%x6
        mov     [%%pDst + 8*30], %%x7

        ;; ----------------
        ;; finalize -- add in diagonal squares
        ;; ----------------
        mov     %%x0, [%%pDst + 8*1]
        mov     %%x1, [%%pDst + 8*2]
        mov     %%x2, [%%pDst + 8*3]
        mov     %%x3, [%%pDst + 8*4]
        mov     %%x4, [%%pDst + 8*5]
        mov     %%x5, [%%pDst + 8*6]
        mov     %%x6, [%%pDst + 8*7]
        mov     %%x7, [%%pDst + 8*8]

        mov     rax, [%%pA + 8*4]
        mul     rax
        mov     %%x8, rax
        mov     %%x9, rdx

        add     %%x0, %%x0
        adc     %%x1, %%x1
        adc     %%x2, %%x2
        adc     %%x3, %%x3
        adc     %%x4, %%x4
        adc     %%x5, %%x5
        adc     %%x6, %%x6
        adc     %%x7, %%x7
        adc     %%x9, 0

        mov     rax, [%%pA + 8*0]
        mul     rax
        mov     [%%pDst + 8*0], rax
        mov     %%A, rdx

        FINALIZE %%pA + 8*0, %%pDst + 8*0, %%A, %%t0, %%x8, %%x0, %%x1, %%x2, %%x3, %%x4, %%x5, %%x6, %%x7

        ; %%t0 has 0/1 in column 9
        ; %%x9 has a full value in column 9

        ;; ----------------

        mov     %%x0, [%%pDst + 8*9]
        mov     %%x1, [%%pDst + 8*10]
        mov     %%x2, [%%pDst + 8*11]
        mov     %%x3, [%%pDst + 8*12]
        mov     %%x4, [%%pDst + 8*13]
        mov     %%x5, [%%pDst + 8*14]
        mov     %%x6, [%%pDst + 8*15]
        mov     %%x7, [%%pDst + 8*16]

        mov     rax, [%%pA + 8*8]
        mul     rax
        mov     %%x8, rax
        mov     %%A, rdx

        add     %%x0, %%x0
        adc     %%x1, %%x1
        adc     %%x2, %%x2
        adc     %%x3, %%x3
        adc     %%x4, %%x4
        adc     %%x5, %%x5
        adc     %%x6, %%x6
        adc     %%x7, %%x7
        adc     %%A, 0

        add     %%x0, %%t0

        FINALIZE %%pA + 8*4, %%pDst + 8*8, %%x9, %%t0, %%x8, %%x0, %%x1, %%x2, %%x3, %%x4, %%x5, %%x6, %%x7

        ; %%t0 has 0/1 in column 17
        ; %%A has a full value in column 17

        ;; ----------------

        mov     %%x0, [%%pDst + 8*17]
        mov     %%x1, [%%pDst + 8*18]
        mov     %%x2, [%%pDst + 8*19]
        mov     %%x3, [%%pDst + 8*20]
        mov     %%x4, [%%pDst + 8*21]
        mov     %%x5, [%%pDst + 8*22]
        mov     %%x6, [%%pDst + 8*23]
        mov     %%x7, [%%pDst + 8*24]

        mov     rax, [%%pA + 8*12]
        mul     rax
        mov     %%x8, rax
        mov     %%x9, rdx

        add     %%x0, %%x0
        adc     %%x1, %%x1
        adc     %%x2, %%x2
        adc     %%x3, %%x3
        adc     %%x4, %%x4
        adc     %%x5, %%x5
        adc     %%x6, %%x6
        adc     %%x7, %%x7
        adc     %%x9, 0

        add     %%x0, %%t0

        FINALIZE %%pA + 8*8, %%pDst + 8*16, %%A, %%t0, %%x8, %%x0, %%x1, %%x2, %%x3, %%x4, %%x5, %%x6, %%x7

        ; %%t0 has 0/1 in column 25
        ; %%A has a full value in column 25

        ;; ----------------

        mov     %%x0, [%%pDst + 8*25]
        mov     %%x1, [%%pDst + 8*26]
        mov     %%x2, [%%pDst + 8*27]
        mov     %%x3, [%%pDst + 8*28]
        mov     %%x4, [%%pDst + 8*29]
        mov     %%x5, [%%pDst + 8*30]

        mov     rax, [%%pA + 8*15]
        mul     rax
        mov     %%x8, rax
        mov     %%A, rdx

        add     %%x0, %%x0
        adc     %%x1, %%x1
        adc     %%x2, %%x2
        adc     %%x3, %%x3
        adc     %%x4, %%x4
        adc     %%x5, %%x5
        adc     %%A, 0

        add     %%x0, %%t0

        ; FINALIZE

        mov     rax, [%%pA + 8*13]
        mul     rax

        add     %%x0, %%x9
        adc     %%x1, rax
        adc     rdx, 0

        mov     %%x9, rdx
        mov     [%%pDst + 8*25], %%x0
        mov     [%%pDst + 8*26], %%x1

        ;; ----------------

        mov     rax, [%%pA + 8*14]
        mul     rax

        add     %%x2, %%x9
        adc     %%x3, rax
        adc     rdx, 0

        mov     %%x9, rdx

        mov     [%%pDst + 8*27], %%x2
        mov     [%%pDst + 8*28], %%x3

        ;; ----------------

        add     %%x4, %%x9
        adc     %%x5, %%x8
        adc     %%A, 0

        mov     [%%pDst + 8*29], %%x4
        mov     [%%pDst + 8*30], %%x5
        mov     [%%pDst + 8*31], %%A
%endmacro



; Swizzle Macros

; macro to copy data from flat space to swizzled table
; MACRO swizzle pDst, pSrc, tmp1, tmp2
; pDst and pSrc are modified
%macro  swizzle 4
%define %%pDst  %1
%define %%pSrc  %2
%define %%tmp1  %3
%define %%tmp2  %4
        mov     %%tmp1, 16
%%loop:
        mov     %%tmp2, [%%pSrc]
        mov     [%%pDst], bx
        shr     %%tmp2, 16
        mov     [%%pDst + 64*1], bx
        shr     %%tmp2, 16
        mov     [%%pDst + 64*2], bx
        shr     %%tmp2, 16
        mov     [%%pDst + 64*3], bx

        add     %%pSrc, 8
        add     %%pDst, 64*4
        dec     %%tmp1
        jnz     %%loop
%endmacro


; macro to copy data from swizzled table to  flat space
; MACRO unswizzle       pDst, pSrc, tmp*3
%macro  unswizzle 5
%define %%pDst  %1
%define %%pSrc  %2
%define %%cnt   %3
%define %%d0    %4
%define %%d1    %5
        mov     %%cnt, 8
%%loop:
        movzx   %%d0, word [%%pSrc + 64*3 + 256*0]
        movzx   %%d1, word [%%pSrc + 64*3 + 256*1]
        shl     %%d0, 16
        shl     %%d1, 16
        mov     %%d0 %+ w, [%%pSrc + 64*2 + 256*0]
        mov     %%d1 %+ w, [%%pSrc + 64*2 + 256*1]
        shl     %%d0, 16
        shl     %%d1, 16
        mov     %%d0 %+ w, [%%pSrc + 64*1 + 256*0]
        mov     %%d1 %+ w, [%%pSrc + 64*1 + 256*1]
        shl     %%d0, 16
        shl     %%d1, 16
        mov     %%d0 %+ w, [%%pSrc + 64*0 + 256*0]
        mov     %%d1 %+ w, [%%pSrc + 64*0 + 256*1]
        mov     [%%pDst + 8*0], %%d0
        mov     [%%pDst + 8*1], %%d1
        add     %%pSrc, 256*2
        add     %%pDst, 8*2
        sub     %%cnt, 1
        jnz     %%loop
%endmacro


; Utility macros for Reduction
; clobbers rax and rdx
%macro reduction_first 14
%define %%pA    %1
%define %%SRC2  %2
%define %%X7    %3
%define %%X6    %4
%define %%X5    %5
%define %%X4    %6
%define %%X3    %7
%define %%X2    %8
%define %%X1    %9
%define %%X0    %10
%define %%red_counter   %11
%define %%STACK_DEPTH   %12
%define %%OP    %13
%define %%TMP   %14
        mov     rax, [%%pA + 8*0]
        mul     %%X0
        mov     [pX1 + 8*%%red_counter + %%STACK_DEPTH], rax
        mov     %%OP, rax

        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, -, %%SRC2, %%OP, %%TMP, -
%endmacro

; clobbers rax and rdx
%macro reduction_second 14
%define %%pDst  %1
%define %%SRC2  %2
%define %%X7    %3
%define %%X6    %4
%define %%X5    %5
%define %%X4    %6
%define %%X3    %7
%define %%X2    %8
%define %%X1    %9
%define %%X0    %10
%define %%red_counter   %11
%define %%STACK_DEPTH   %12
%define %%OP    %13
%define %%TMP   %14

        mov     %%OP, [pX1 + 8*%%red_counter + %%STACK_DEPTH]

        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0,  [%%pDst+8*%%red_counter], %%SRC2, %%OP, %%TMP, store

%endmacro


; -----------------------------------------------------------------------

; Data Structures

; Reduce Data
; temp space used to store intermediate results of the reduction operation
%define X1_offset       0               ; 8 qwords
%define X2_offset       X1_offset + 8*8 ; 8 qwords
%define Carries_offset  X2_offset + 8*8 ; 1 qword

; amount of total temp space
%define Red_Data_Size   Carries_offset + 1*8    ; (Total 17 qwords)

; pointers to the individual temp spaces allocated
%define pX1             Reduce_Data + X1_offset
%define pX2             Reduce_Data + X2_offset
%define pCarries        Reduce_Data + Carries_offset

; rsp & garray need to be aligned to 64 Bytes
%define garray_offset           0
%define rsp_offset              8*8*64 + garray_offset
%define pResult_offset          8*1 + rsp_offset
%define pG_offset               8*1 + pResult_offset
%define pExp_offset             8*1 + pG_offset
%define pData_offset            8*1 + pExp_offset
%define i_offset                8*1 + pData_offset
%define pg_offset               8*1 + i_offset
%define GT_offset               8*1 + pg_offset
%define GT2_offset              8*16 + GT_offset
%define tmp32_offset            8*16 + GT2_offset
%define MZ_offset               8*32 + tmp32_offset
%define tmp16_offset            8*32 + MZ_offset
%define exp_offset              8*16 + tmp16_offset
%define loop_idx_offset         8*17 + exp_offset
%define red_result_addr_offset  8*1 + loop_idx_offset
%define Reduce_Data_offset      8*1 + red_result_addr_offset
%define mem_size                Reduce_Data_offset + Red_Data_Size

%define garray                  rsp+garray_offset
%define rsp_saved               rsp+rsp_offset
%define pResult                 rsp+pResult_offset
%define pG                      rsp+pG_offset
%define pExp                    rsp+pExp_offset
%define pData                   rsp+pData_offset
%define i                       rsp+i_offset
%define pg                      rsp+pg_offset
%define GT                      rsp+GT_offset
%define GT2                     rsp+GT2_offset
%define tmp32                   rsp+tmp32_offset
%define MZ                      rsp+MZ_offset
%define tmp16                   rsp+tmp16_offset
%define exp                     rsp+exp_offset
%define loop_idx                rsp+loop_idx_offset
%define red_res_addr            rsp+red_result_addr_offset
%define Reduce_Data             rsp+Reduce_Data_offset

; data structure for precomputed data
; struct MOD_EXP_1024_DATA {
;       UINT64 R[16];   // 2^1024 % m
;       UINT64 R2[16];  // 2^2048 % m
;       UINT64 M[16];   // m
;       UINT64 m_1[1];  // (-1/m) % 2^64
;

%define R       0
%define R2      128     ; = 8 * 8 * 2
%define M       256     ; = 8 * 8 * 4   //      += 8 * 8 * 2
%define m_1     384     ; = 8 * 8 * 6   //      += 8 * 8 * 2


; -------------------------------------------------------------
; Functions

align 32

;; mont_reduce(u64 *x,               // 2048 bits, 32 qwords
;;             MOD_EXP_1024_DATA *data,
;;             u64 *r)               //  1024 bits,  16 qwords
;;
;; Input:  x (number to be reduced): tmp32 (Implicit)
;;         data (reduce data):       [pData] (Implicit)
;; Output: r (result):               Address in [red_res_addr]
;; Do a Montgomery reduction of x (using data) and store the results in r. 

mont_reduce:
%define STACK_DEPTH 8*1
        mov     rsi, [pData + STACK_DEPTH]
        lea     rsi, [rsi + m_1]

        mov     rdi, rsi                ; M
        sub     rdi, (m_1 - M)

        mov     r8,  [tmp32 + 8*0 + STACK_DEPTH]
        mov     r9,  [tmp32 + 8*1 + STACK_DEPTH]
        mov     r10, [tmp32 + 8*2 + STACK_DEPTH]
        mov     r11, [tmp32 + 8*3 + STACK_DEPTH]
        mov     r12, [tmp32 + 8*4 + STACK_DEPTH]
        mov     r13, [tmp32 + 8*5 + STACK_DEPTH]
        mov     r14, [tmp32 + 8*6 + STACK_DEPTH]
        mov     r15, [tmp32 + 8*7 + STACK_DEPTH]

        reduction_first rsi, rdi, r15, r14, r13, r12, r11, r10, r9 , r8 , 0, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r8 , r15, r14, r13, r12, r11, r10, r9 , 1, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r9 , r8 , r15, r14, r13, r12, r11, r10, 2, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r10, r9 , r8 , r15, r14, r13, r12, r11, 3, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r11, r10, r9 , r8 , r15, r14, r13, r12, 4, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r12, r11, r10, r9 , r8 , r15, r14, r13, 5, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r13, r12, r11, r10, r9 , r8 , r15, r14, 6, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r14, r13, r12, r11, r10, r9 , r8 , r15, 7, STACK_DEPTH, rbp, rbx

        mov     rcx, [red_res_addr  + STACK_DEPTH ]

        reduction_second rcx + 8*8, rdi + 8*8, r15, r14, r13, r12, r11, r10, r9 , r8 , 0, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r8 , r15, r14, r13, r12, r11, r10, r9 , 1, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r9 , r8 , r15, r14, r13, r12, r11, r10, 2, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r10, r9 , r8 , r15, r14, r13, r12, r11, 3, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r11, r10, r9 , r8 , r15, r14, r13, r12, 4, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r12, r11, r10, r9 , r8 , r15, r14, r13, 5, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r13, r12, r11, r10, r9 , r8 , r15, r14, 6, STACK_DEPTH, rbp, rbx
        reduction_second rcx + 8*8, rdi + 8*8, r14, r13, r12, r11, r10, r9 , r8 , r15, 7, STACK_DEPTH, rbp, rbx

        mov     [pX2 + 8*0 + STACK_DEPTH], r8
        mov     [pX2 + 8*1 + STACK_DEPTH], r9
        mov     [pX2 + 8*2 + STACK_DEPTH], r10
        mov     [pX2 + 8*3 + STACK_DEPTH], r11
        mov     [pX2 + 8*4 + STACK_DEPTH], r12
        mov     [pX2 + 8*5 + STACK_DEPTH], r13
        mov     [pX2 + 8*6 + STACK_DEPTH], r14
        mov     [pX2 + 8*7 + STACK_DEPTH], r15

        mov     r8, [tmp32 + 8*8 + STACK_DEPTH]
        mov     r9, [tmp32 + 8*9 + STACK_DEPTH]
        mov     r10, [tmp32 + 8*10 + STACK_DEPTH]
        mov     r11, [tmp32 + 8*11 + STACK_DEPTH]
        mov     r12, [tmp32 + 8*12 + STACK_DEPTH]
        mov     r13, [tmp32 + 8*13 + STACK_DEPTH]
        mov     r14, [tmp32 + 8*14 + STACK_DEPTH]
        mov     r15, [tmp32 + 8*15 + STACK_DEPTH]

        xor     rax, rax
        add     r8, [rcx + 8*8]
        adc     r9, [rcx + 8*9]
        adc     r10, [rcx + 8*10]
        adc     r11, [rcx + 8*11]
        adc     r12, [rcx + 8*12]
        adc     r13, [rcx + 8*13]
        adc     r14, [rcx + 8*14]
        adc     r15, [rcx + 8*15]
        adc     rax, 0
        mov     [pCarries + STACK_DEPTH], rax

        reduction_first rsi, rdi, r15, r14, r13, r12, r11, r10, r9 , r8 , 0, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r8 , r15, r14, r13, r12, r11, r10, r9 , 1, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r9 , r8 , r15, r14, r13, r12, r11, r10, 2, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r10, r9 , r8 , r15, r14, r13, r12, r11, 3, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r11, r10, r9 , r8 , r15, r14, r13, r12, 4, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r12, r11, r10, r9 , r8 , r15, r14, r13, 5, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r13, r12, r11, r10, r9 , r8 , r15, r14, 6, STACK_DEPTH, rbp, rbx
        reduction_first rsi, rdi, r14, r13, r12, r11, r10, r9 , r8 , r15, 7, STACK_DEPTH, rbp, rbx

        mov     rcx, [red_res_addr  + STACK_DEPTH ]

        reduction_second rcx, rdi + 8*8, r15, r14, r13, r12, r11, r10, r9 , r8 , 0, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r8 , r15, r14, r13, r12, r11, r10, r9 , 1, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r9 , r8 , r15, r14, r13, r12, r11, r10, 2, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r10, r9 , r8 , r15, r14, r13, r12, r11, 3, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r11, r10, r9 , r8 , r15, r14, r13, r12, 4, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r12, r11, r10, r9 , r8 , r15, r14, r13, 5, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r13, r12, r11, r10, r9 , r8 , r15, r14, 6, STACK_DEPTH, rbp, rbx
        reduction_second rcx, rdi + 8*8, r14, r13, r12, r11, r10, r9 , r8 , r15, 7, STACK_DEPTH, rbp, rbx

        mov     [rcx + 8*8], r8
        mov     [rcx + 8*9], r9
        mov     [rcx + 8*10], r10
        mov     [rcx + 8*11], r11
        mov     [rcx + 8*12], r12
        mov     [rcx + 8*13], r13
        mov     [rcx + 8*14], r14
        mov     [rcx + 8*15], r15

        mov     r8, [pX2 + 8*0 + STACK_DEPTH]
        mov     r9, [pX2 + 8*1 + STACK_DEPTH]
        mov     r10, [pX2 + 8*2 + STACK_DEPTH]
        mov     r11, [pX2 + 8*3 + STACK_DEPTH]
        mov     r12, [pX2 + 8*4 + STACK_DEPTH]
        mov     r13, [pX2 + 8*5 + STACK_DEPTH]
        mov     r14, [pX2 + 8*6 + STACK_DEPTH]
        mov     r15, [pX2 + 8*7 + STACK_DEPTH]
        xor     rbx, rbx
        mov     rax, [pCarries + STACK_DEPTH]
        shr     rax, 1

        adc     r8, [tmp32 + 8*16 + STACK_DEPTH]
        adc     r9, [tmp32 + 8*17 + STACK_DEPTH]
        adc     r10, [tmp32 + 8*18 + STACK_DEPTH]
        adc     r11, [tmp32 + 8*19 + STACK_DEPTH]
        adc     r12, [tmp32 + 8*20 + STACK_DEPTH]
        adc     r13, [tmp32 + 8*21 + STACK_DEPTH]
        adc     r14, [tmp32 + 8*22 + STACK_DEPTH]
        adc     r15, [tmp32 + 8*23 + STACK_DEPTH]
        adc     rax, 0

        add     r8, [rcx + 8*0]
        adc     r9, [rcx + 8*1]
        adc     r10, [rcx + 8*2]
        adc     r11, [rcx + 8*3]
        adc     r12, [rcx + 8*4]
        adc     r13, [rcx + 8*5]
        adc     r14, [rcx + 8*6]
        adc     r15, [rcx + 8*7]

        mov     [rcx + 8*0], r8
        mov     [rcx + 8*1], r9
        mov     [rcx + 8*2], r10
        mov     [rcx + 8*3], r11
        mov     [rcx + 8*4], r12
        mov     [rcx + 8*5], r13
        mov     [rcx + 8*6], r14
        mov     [rcx + 8*7], r15
        
        mov     r8, [tmp32 + 8*24 + STACK_DEPTH]
        mov     r9, [tmp32 + 8*25 + STACK_DEPTH]
        mov     r10, [tmp32 + 8*26 + STACK_DEPTH]
        mov     r11, [tmp32 + 8*27 + STACK_DEPTH]
        mov     r12, [tmp32 + 8*28 + STACK_DEPTH]
        mov     r13, [tmp32 + 8*29 + STACK_DEPTH]
        mov     r14, [tmp32 + 8*30 + STACK_DEPTH]
        mov     r15, [tmp32 + 8*31 + STACK_DEPTH]

        adc     r8, [rcx + 8*8]
        adc     r9, [rcx + 8*9]
        adc     r10, [rcx + 8*10]
        adc     r11, [rcx + 8*11]
        adc     r12, [rcx + 8*12]
        adc     r13, [rcx + 8*13]
        adc     r14, [rcx + 8*14]
        adc     r15, [rcx + 8*15]
        adc     rbx, 0

        add     r8, rax
        adc     r9, 0
        adc     r10, 0
        adc     r11, 0
        adc     r12, 0
        adc     r13, 0
        adc     r14, 0
        adc     r15, 0
        adc     rbx, 0

        mov     [rcx + 8*8], r8
        mov     [rcx + 8*9], r9
        mov     [rcx + 8*10], r10
        mov     [rcx + 8*11], r11
        mov     [rcx + 8*12], r12
        mov     [rcx + 8*13], r13
        mov     [rcx + 8*14], r14
        mov     [rcx + 8*15], r15
        
        op_mem_mem      sub, [rcx+8*0], [rcx+8*0], [MZ + STACK_DEPTH + rbx*8 + 8*0], rax
        op_mem_mem      sbb, [rcx+8*1], [rcx+8*1], [MZ + STACK_DEPTH + rbx*8 + 8*2], rax
        op_mem_mem      sbb, [rcx+8*2], [rcx+8*2], [MZ + STACK_DEPTH + rbx*8 + 8*4], rax
        op_mem_mem      sbb, [rcx+8*3], [rcx+8*3], [MZ + STACK_DEPTH + rbx*8 + 8*6], rax
        op_mem_mem      sbb, [rcx+8*4], [rcx+8*4], [MZ + STACK_DEPTH + rbx*8 + 8*8], rax
        op_mem_mem      sbb, [rcx+8*5], [rcx+8*5], [MZ + STACK_DEPTH + rbx*8 + 8*10], rax
        op_mem_mem      sbb, [rcx+8*6], [rcx+8*6], [MZ + STACK_DEPTH + rbx*8 + 8*12], rax
        op_mem_mem      sbb, [rcx+8*7], [rcx+8*7], [MZ + STACK_DEPTH + rbx*8 + 8*14], rax
        op_mem_reg_mem  sbb, [rcx+8*8],  r8,  [MZ + STACK_DEPTH + rbx*8 + 8*16], rax
        op_mem_reg_mem  sbb, [rcx+8*9],  r9,  [MZ + STACK_DEPTH + rbx*8 + 8*18], rax
        op_mem_reg_mem  sbb, [rcx+8*10], r10, [MZ + STACK_DEPTH + rbx*8 + 8*20], rax
        op_mem_reg_mem  sbb, [rcx+8*11], r11, [MZ + STACK_DEPTH + rbx*8 + 8*22], rax
        op_mem_reg_mem  sbb, [rcx+8*12], r12, [MZ + STACK_DEPTH + rbx*8 + 8*24], rax
        op_mem_reg_mem  sbb, [rcx+8*13], r13, [MZ + STACK_DEPTH + rbx*8 + 8*26], rax
        op_mem_reg_mem  sbb, [rcx+8*14], r14, [MZ + STACK_DEPTH + rbx*8 + 8*28], rax
        op_mem_reg_mem  sbb, [rcx+8*15], r15, [MZ + STACK_DEPTH + rbx*8 + 8*30], rax

ret


;; mont_mul_1024 : subroutine to compute (Src1 * Src2) % M (all 1024-bits)
;; Input:  src1: Address of source 1: rdi
;;         src2: Address of source 2: rsi
;; Output: dst:  Address of destination: [red_res_addr]
;;         src2 and result also in: r9, r8, r15, r14, r13, r12, r11, r10
;; Temp:   Clobbers [tmp32], all registers

mont_mul_1024:
%define STACK_DEPTH 8*1
        ; multiply tmp = src1 * src2
        ; For multiply: dst = rcx, src1 = rdi, src2 = rsi
        MUL_1024_1024   rcx, rdi, rsi, r15, r14, r13, r12, r11, r10, r9, r8, rbp, rbx

        ;;;;;;;;;;;;;;;;
        ; Dst = tmp % m
        ; Call reduce(tmp, data, dst)
        mov     rcx, [red_res_addr + STACK_DEPTH]
        
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce


; ------------------------------------------------------------------------

;; sqr_reduce : subroutine to compute Result = reduce(Result * Result)
;; Output: dst:  Address of destination: [red_res_addr]
;; Temp:   Clobbers [tmp32], all registers

sqr_reduce_1024:
%define STACK_DEPTH 8
        SQR_1024 tmp32 + STACK_DEPTH, rdi, rbx, rsi, rcx, rbp, r15, r14, r13, r12, r11, r10, r9, r8
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce


; ------------------------------------------------------------------------
;; MAIN FUNCTION

;void rsax_mod_exp_1024(
;       u64 *result, // 1024 bits, 16 qwords
;       u64 *g,      // 1024 bits, 16 qwords
;       u64 *exp,    // 1024 bits, 16 qwords
;       MOD_EXP_1024_DATA *data);
        

global _rsax_mod_exp_1024
_rsax_mod_exp_1024:

%ifdef WIN_ABI 
        push    rsi
        push    rdi
%endif
        push    rbp
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        ;; adjust stack down and then align it with cache boundary
        mov     rbp, rsp

%ifdef WIN_ABI  
        ; __chkstk is responsible for probing the to-be-allocated stack range, to ensure that the stack is extended properly
        ; it is needed becase we are allocating stack space greater than a page size
        mov     rax, mem_size
        call    __chkstk
%endif
        sub     rsp, mem_size
        and     rsp, ~63

        ;; store previous stack pointer and arguments
        mov     [rsp_saved], rbp
        mov     [pResult], arg1
        mov     [pG],      arg2
        mov     [pData],   arg4
        
        ; Copy exponent onto stack
%assign j 0
%rep 16 
        mov     rax, [arg3 + 8*j]
        mov     [exp + 8*j], rax
%assign j (j+1)
%endrep
        xor     rax, rax
        mov     [exp + 8*j], rax
        
        ; Interleave M with 0

        mov     rsi, [pData]
        add     rsi, M

%assign j 0
%rep 16 
        mov     [MZ + 8*(2*j)], rax

        mov     rcx, [rsi + 8*j]
        mov     [MZ + 8*(2*j+1)], rcx
%assign j (j+1)
%endrep

        ; R = 2^1024 mod m
        ; Compute G0 = (g^0)*R = R  
        mov     rsi, [pData]
        add     rsi, R

        lea     rcx, [tmp16]

%assign j 0
%rep 16
        mov     rax, [rsi + 8*j]
        mov     [rcx + 8*j], rax
        %assign j (j+1)
%endrep

        lea     rsi, [garray]
        swizzle rsi, rcx, rax, rbx

        ; Compute G1 = (g^1)*R = MM(R^2, g)   
        lea     rcx, [tmp32]
        mov     rsi, [pData]
        add     rsi, R2
        mov     rdi, [pG]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024

        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*1
        swizzle rsi, rcx, rax, rbx

        ; Compute G2 = (g^2)*R = SQ(G1)      
        lea     rax, [GT2]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*2
        swizzle rsi, rcx, rax, rbx

        ; Compute G4 = (g^4)*R = SQ(G2)          
        lea     rdi, [GT2]
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*4
        swizzle rsi, rcx, rax, rbx

        ; Compute G8 = (g^8)*R = SQ(G4)          
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*8
        swizzle rsi, rcx, rax, rbx

        ; Compute G16 = (g^16)*R = SQ(G8)        
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*16
        swizzle rsi, rcx, rax, rbx

        ; Compute G3 = (g^3)*R = MM(G2, G1)      
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*3
        swizzle rsi, rcx, rax, rbx

        ; Compute G6 = (g^6)*R = SQ(G3)          
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*6
        swizzle rsi, rcx, rax, rbx

        ; Compute G12 = (g^12)*R = SQ(G6)        
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*12
        swizzle rsi, rcx, rax, rbx

        ; Compute G24 = (g^24)*R = SQ(G12)       
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*24
        swizzle rsi, rcx, rax, rbx

        ; Compute G5 = (g^5)*R = MM(G2, G3)      
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*5
        swizzle rsi, rcx, rax, rbx

        ; Compute G10 = (g^10)*R = SQ(G5)        
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*10
        swizzle rsi, rcx, rax, rbx

        ; Compute G20 = (g^20)*R = SQ(G10)       
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*20
        swizzle rsi, rcx, rax, rbx

        ; Compute G7 = (g^7)*R = MM(G2, G5)      
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*7
        swizzle rsi, rcx, rax, rbx

        ; Compute G14 = (g^14)*R = SQ(G7)        
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*14
        swizzle rsi, rcx, rax, rbx

        ; Compute G28 = (g^28)*R = SQ(G14)       
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*28
        swizzle rsi, rcx, rax, rbx

        ; Compute G9 = (g^9)*R = MM(G2, G7)      
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*9
        swizzle rsi, rcx, rax, rbx

        ; Compute G18 = (g^18)*R = SQ(G9)
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*18
        swizzle rsi, rcx, rax, rbx

        ; Compute G11 = (g^11)*R = MM(G2, G9);
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*11
        swizzle rsi, rcx, rax, rbx

        ; Compute G22 = (g^22)*R = SQ(G11)       
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*22
        swizzle rsi, rcx, rax, rbx

        ; Compute G13 = (g^13)*R = MM(G2, G11);
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*13
        swizzle rsi, rcx, rax, rbx

        ; Compute G26 = (g^26)*R = SQ(G13)       
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*26
        swizzle rsi, rcx, rax, rbx

        ; Compute G15 = (g^15)*R = MM(G2, G13)
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*15
        swizzle rsi, rcx, rax, rbx

        ; Compute G30 = (g^30)*R = SQ(G15)
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*30
        swizzle rsi, rcx, rax, rbx

        ; Compute G17 = (g^17)*R = MM(G2, G15)
        lea     rcx, [tmp32]
        lea     rdi, [GT]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*17
        swizzle rsi, rcx, rax, rbx

        ; Compute G19 = (g^19)*R = MM(G2, G17)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*19
        swizzle rsi, rcx, rax, rbx

        ; Compute G21 = (g^21)*R = MM(G2, G19)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*21
        swizzle rsi, rcx, rax, rbx

        ; Compute G23 = (g^23)*R = MM(G2, G21)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*23
        swizzle rsi, rcx, rax, rbx

        ; Compute G25 = (g^25)*R = MM(G2, G23)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*25
        swizzle rsi, rcx, rax, rbx

        ; Compute G27 = (g^27)*R = MM(G2, G25)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*27
        swizzle rsi, rcx, rax, rbx

        ; Compute G29 = (g^29)*R = MM(G2, G27)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*29
        swizzle rsi, rcx, rax, rbx

        ; Compute G31 = (g^31)*R = MM(G2, G29)
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        lea     rsi, [garray]
        add     rsi, 2*31
        swizzle rsi, rcx, rax, rbx

        ; Do exponentiation

        ; Initialize result to G[exp{1024:1020}]
        mov     eax, [exp + 126]
        mov     rdx, rax
        shr     rax, 11
        and     edx, 0x07FF
        mov     [exp + 126], edx
        lea     rsi, [garray + rax*2]
        mov     rdx, [pResult]
        unswizzle       rdx, rsi,  rbp, rbx, rax

        ; Loop variables
        ; rcx = [loop_idx] = index: 1020-5 to 0 by 5
        mov     qword [loop_idx], 1015
        
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi

        jmp     sqr_4

main_loop:
        mov     rdi, [pResult]
        call    sqr_reduce_1024
sqr_4:
        mov     rdi, [pResult]
        call    sqr_reduce_1024
        mov     rdi, [pResult]
        call    sqr_reduce_1024
        mov     rdi, [pResult]
        call    sqr_reduce_1024
        mov     rdi, [pResult]
        call    sqr_reduce_1024

        ; Do multiply, first look up proper value in Garray
        mov     rcx, [loop_idx] ; bit index
        mov     rax, rcx
        shr     rax, 4          ; rax is word pointer
        mov     edx, [exp + rax*2]
        and     rcx, 15
        shr     rdx, cl
        and     rdx, 0x1F

        lea     rsi, [garray + rdx*2]
        lea     rdx, [tmp16]
        mov     rdi, rdx
        unswizzle       rdx, rsi, rbp, rbx, rax
        ; rdi = tmp = pG

        ; Call mod_mul_a1(pDst,  pSrc1, pSrc2, pM, pData)
        ;                 result result pG     M   Data
        lea     rdi, [tmp16]
        lea     rcx, [tmp32]    
        
        mov     rsi, [pResult]
        call    mont_mul_1024

        ; finish loop
        mov     rcx, [loop_idx]
        sub     rcx, 5
        mov     [loop_idx], rcx
        jge     main_loop

        ; transform result out of Montgomery space
        ; mont_mul(result, result, one, m, data);

        mov     rdx, [pResult]
        lea     rcx, [tmp32]
        
%assign j 0
%rep 16
        mov     rax, [rdx + 8*j]
        mov     [rcx + 8*j], rax
%assign j (j+1)
%endrep
        xor     rax, rax
%rep 16
        mov     [rcx + 8*j], rax
%assign j j+1
%endrep
        
        mov     rcx, [pResult]
        mov     [red_res_addr], rcx
        call    mont_reduce

        
        ; If result > m, subract m
        ; load result into r15:r8
        mov     rdx, 1
        mov     rax, [pResult]
        mov     r8, [rax+8*0]
        mov     r9, [rax+8*1]
        mov     r10, [rax+8*2]
        mov     r11, [rax+8*3]
        mov     r12, [rax+8*4]
        mov     r13, [rax+8*5]
        mov     r14, [rax+8*6]
        mov     r15, [rax+8*7]

        ; subtract m
        mov     rbx, [pData]
        add     rbx, M
        
        sub     r8, [rbx+8*0]
        op_reg_mem      sbb, r9, [rbx+8*1], rcx
        sbb     r10, [rbx+8*2]
        op_reg_mem      sbb, r11, [rbx+8*3], rcx
        sbb     r12, [rbx+8*4]
        op_reg_mem      sbb, r13, [rbx+8*5], rcx
        sbb     r14, [rbx+8*6]
        sbb     r15, [rbx+8*7]
        sbb     rdx, 0
        
        lea     rdi, [tmp32]
        mov     [rdi], r8
        mov     [rdi+8*1], r9
        mov     [rdi+8*2], r10
        mov     [rdi+8*3], r11
        mov     [rdi+8*4], r12
        mov     [rdi+8*5], r13
        mov     [rdi+8*6], r14
        mov     [rdi+8*7], r15
        
        mov     r8, [rax+8*8]
        mov     r9, [rax+8*9]
        mov     r10, [rax+8*10]
        mov     r11, [rax+8*11]
        mov     r12, [rax+8*12]
        mov     r13, [rax+8*13]
        mov     r14, [rax+8*14]
        mov     r15, [rax+8*15]
        
        sub     rdx, 1
        sbb     r8, [rbx+8*8]
        op_reg_mem      sbb, r9, [rbx+8*9], rcx
        sbb     r10, [rbx+8*10]
        op_reg_mem      sbb, r11, [rbx+8*11], rcx
        sbb     r12, [rbx+8*12]
        op_reg_mem      sbb, r13, [rbx+8*13], rcx
        sbb     r14, [rbx+8*14]
        sbb     r15, [rbx+8*15]

        ; if Carry is clear, replace result with difference
        mov     rbx, [rax+8*0]
        mov     rsi, [rdi]
        cmovnc  rbx, rsi
        mov     [rax+8*0], rbx

        mov     rbx, [rax+8*1]
        mov     rsi, [rdi + 8*1]
        cmovnc  rbx, rsi
        mov     [rax+8*1], rbx

        mov     rbx, [rax+8*2]
        mov     rsi, [rdi + 8*2]
        cmovnc  rbx, rsi
        mov     [rax+8*2], rbx

        mov     rbx, [rax+8*3]
        mov     rsi, [rdi + 8*3]
        cmovnc  rbx, rsi
        mov     [rax+8*3], rbx

        mov     rbx, [rax+8*4]
        mov     rsi, [rdi + 8*4]
        cmovnc  rbx, rsi
        mov     [rax+8*4], rbx

        mov     rbx, [rax+8*5]
        mov     rsi, [rdi + 8*5]
        cmovnc  rbx, rsi
        mov     [rax+8*5], rbx

        mov     rbx, [rax+8*6]
        mov     rsi, [rdi + 8*6]
        cmovnc  rbx, rsi
        mov     [rax+8*6], rbx

        mov     rbx, [rax+8*7]
        mov     rsi, [rdi + 8*7]
        cmovnc  rbx, rsi
        mov     [rax+8*7], rbx

        mov     rbx, [rax+8*8]
        cmovnc  rbx, r8
        mov     [rax+8*8], rbx

        mov     rbx, [rax+8*9]
        cmovnc  rbx, r9
        mov     [rax+8*9], rbx

        mov     rbx, [rax+8*10]
        cmovnc  rbx, r10
        mov     [rax+8*10], rbx

        mov     rbx, [rax+8*11]
        cmovnc  rbx, r11
        mov     [rax+8*11], rbx

        mov     rbx, [rax+8*12]
        cmovnc  rbx, r12
        mov     [rax+8*12], rbx

        mov     rbx, [rax+8*13]
        cmovnc  rbx, r13
        mov     [rax+8*13], rbx

        mov     rbx, [rax+8*14]
        cmovnc  rbx, r14
        mov     [rax+8*14], rbx

        mov     rbx, [rax+8*15]
        cmovnc  rbx, r15
        mov     [rax+8*15], rbx
        
        mov     rsp, [rsp_saved]
        
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        pop     rbp
%ifdef WIN_ABI 
        pop     rdi
        pop     rsi
%endif

        ret
