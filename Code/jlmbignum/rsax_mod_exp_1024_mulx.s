;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Authors:
;       Erdinc Ozturk
;       James Guilford
;       Vinodh Gopal
; constant-time modular exponentiation
; mod-exp 1024, with mulx instruction
; single loop windowing code
; fixed windowing with window size of 5 bits
; YASM syntax, x64 instructions
; a version of the YASM supporting mulx instruction is required. 
; 
; void rsax_mod_exp_1024_mulx(
;       UINT64 *result, // 1024 bits, 16 qwords
;       UINT64 *g,      // 1024 bits, 16 qwords
;       UINT64 *exp,    // 1024 bits, 16 qwords
;       MOD_EXP_1024_DATA *data);
;
; struct MOD_EXP_1024_DATA {
;       UINT64 R[16];   // 2^1024 % m
;       UINT64 R2[16];  // 2^2048 % m
;       UINT64 M[16];   // m
;       UINT64 m_1[1];  // (-1/m) % 2^64
;        
; Montgomery Reduction algorithm is used with b = 2^64, n = 16, R = 2^1024, m' = -m^(-1) mod 2^64
; Reference: Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone. Handbook of Applied Cryptography. October 1996.
;
; for WINDOWS*, preprocessor definition WIN_ABI is required.
;       sample command line for WINDOWS*:
;               yasm -Xvc -f x64 -rnasm -pnasm -o "x64\Release\rsax_mod_exp_1024_mulx_adcox.obj" -l "" -g cv8 -D "WIN_ABI" 
; No definition is required for LINUX*
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
;*Other names and brands may be claimed as the property of others.


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


;;;;;;;;;;;;;;;;;;;;;;;;
;; Define utility macros
;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; macro used to replace op reg, mem instructions
; Execute reg-mem opcode using explicit load
; macro op_reg_mem OPCODE, DST, MEM_SRC, TMP
%macro op_reg_mem 4
%define %%OPC   %1      ; instruction
%define %%DST   %2      ; destination (register)
%define %%SRC1  %3      ; source 1 (memory)
%define %%TMP   %4      ; temp (register)
        mov     %%TMP, %%SRC1
        %%OPC   %%DST, %%TMP
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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




;;;;;;;;;;;;;;;;;;;;;;;;;
;; Define squaring macros
;;;;;;;;;;;;;;;;;;;;;;;;;


; rolled sqr
; on non-diagonal terms: do 8x8 triangle, 4x 2x8 square, 8x8 triangle

; MULSTEP_512_sq   MACRO   x0b, x7, x6, x5, x4, x3, x2, x1, x0, x0a, dst, src2, src1_val, tmp
; Macro to do one or part of one diagonal of multiplication
; i.e. do a 64 bit by <= 512 bit multiply
; In: partial sum:                x7 x6 x5 x4 x3 x2 x1 x0
;   src2[] * src1_val           p  p  p  p  p  p  p  p  p
; Out:                         x0 x7 x6 x5 x4 x3 x2 x1
;                                                     [dst]
; uses rax, rdx, and args

%macro MULSTEP_512_sq 14
%define %%X0B   %1
%define %%X7    %2
%define %%X6    %3
%define %%X5    %4
%define %%X4    %5
%define %%X3    %6
%define %%X2    %7
%define %%X1    %8
%define %%X0    %9
%define %%X0A   %10
%define %%DST   %11
%define %%SRC2  %12
%define %%TMP1  %13
%define %%TMP2  %14

%ifnidn %%X0, -
        ; TMP1:X0 = rdx * [SRC2] + X0
        mulx    %%TMP1, rax, [%%SRC2+8*0]       ; TMP1:rax = rdx * [%%SRC2+8*0]
        add     %%X0, rax
        adc     %%TMP1, 0
%endif

%ifnidn %%X0A, -
        mov     %%DST, %%X0A
%endif

%ifnidn %%X1, -
        ; TMP2:X1 = rdx * [SRC2] + X1 + TMP1
        mulx    %%TMP2, rax, [%%SRC2+8*1]       ; TMP2:rax = rdx * [%%SRC2+8*1]
        add     %%X1, rax
        adc     %%TMP2, 0
%ifnidn %%X0, -
        add     %%X1, %%TMP1
        adc     %%TMP2, 0
%endif
%endif

%ifnidn %%X2, -
        ; TMP1:X2 = rdx * [SRC2] + X2 + TMP2
        mulx    %%TMP1, rax, [%%SRC2+8*2]       ; TMP1:rax = rdx * [%%SRC2+8*2]
        add     %%X2, rax
        adc     %%TMP1, 0
%ifnidn %%X1, -
        add     %%X2, %%TMP2
        adc     %%TMP1, 0
%endif
%endif
        

%ifnidn %%X3, -
        ; TMP2:X3 = rdx * [SRC2] + X3 + TMP1
        mulx    %%TMP2, rax, [%%SRC2+8*3]       ; TMP2:rax = rdx * [%%SRC2+8*3]
        add     %%X3, rax
        adc     %%TMP2, 0
%ifnidn %%X2, -
        add     %%X3, %%TMP1
        adc     %%TMP2, 0
%endif
%endif
        

%ifnidn %%X4, -
        ; TMP1:X4 = rdx * [SRC2] + X4 + TMP2
        mulx    %%TMP1, rax, [%%SRC2+8*4]       ; TMP1:rax = rdx * [%%SRC2+8*4]
        add     %%X4, rax
        adc     %%TMP1, 0
%ifnidn %%X3, -
        add     %%X4, %%TMP2
        adc     %%TMP1, 0
%endif
%endif
        

%ifnidn %%X5, -
        ; TMP2:X5 = rdx * [SRC2] + X5 + TMP1
        mulx    %%TMP2, rax, [%%SRC2+8*5]       ; TMP2:rax = rdx * [%%SRC2+8*5]
        add     %%X5, rax
        adc     %%TMP2, 0
%ifnidn %%X4, -
        add     %%X5, %%TMP1
        adc     %%TMP2, 0
%endif
%endif
        

%ifnidn %%X6, -
        ; TMP1:X6 = rdx * [SRC2] + X6 + TMP2
        mulx    %%TMP1, rax, [%%SRC2+8*6]       ; TMP1:rax = rdx * [%%SRC2+8*6]
        add     %%X6, rax
        adc     %%TMP1, 0
%ifnidn %%X5, -
        add     %%X6, %%TMP2
        adc     %%TMP1, 0
%endif
%endif
        

%ifnidn %%X7, -
        ; X0:X7 = rdx * [SRC2] + X7 + TMP1
        mulx    %%X0B, rax, [%%SRC2+8*7]        ; X0:rax = rdx * [%%SRC2+8*7]
        add     %%X7, rax
        adc     %%X0B, 0
%ifnidn %%X6, -
        add     %%X7, %%TMP1
        adc     %%X0B, 0
%endif
%endif
%endmacro


;;;;;;;;;;;;;;;;
; Diagonal Macro
; 64x512  bit multiplication accumulated with 512-bit intermediate result
; 1 QW x 8 QW
; Source 1: rdx register (implicitly defined for mulx instruction)
; Source 2: %%SRC2
; Intermediate result: Registers %%X7:%%X0
; if %%if_store is not '-', result stored in %%X0, %%X7:%%X1, %%DST
; if %%if_store is '-', result stored in %%X0, %%X7:%%X1, lowest QW is discarded

%macro MULSTEP_512 13
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
%define %%TMP1  %11
%define %%TMP2  %12
%define %%TMP3  %13

        mulx    %%TMP1, %%TMP3, [%%SRC2+8*0]
        add     %%TMP3, %%X0
        adc     %%TMP1, 0
        mov     %%DST, %%TMP3

        mulx    %%TMP2, %%X0, [%%SRC2+8*1]
        add     %%X0, %%X1
        adc     %%TMP2, 0
        add     %%X0, %%TMP1
        adc     %%TMP2, 0
        
        mulx    %%TMP1, %%X1, [%%SRC2+8*2]
        add     %%X1, %%X2
        adc     %%TMP1, 0
        add     %%X1, %%TMP2
        adc     %%TMP1, 0
        
        mulx    %%TMP2, %%X2, [%%SRC2+8*3]
        add     %%X2, %%X3
        adc     %%TMP2, 0
        add     %%X2, %%TMP1
        adc     %%TMP2, 0
        
        mulx    %%TMP1, %%X3, [%%SRC2+8*4]
        add     %%X3, %%X4
        adc     %%TMP1, 0
        add     %%X3, %%TMP2
        adc     %%TMP1, 0
        
        mulx    %%TMP2, %%X4, [%%SRC2+8*5]
        add     %%X4, %%X5
        adc     %%TMP2, 0
        add     %%X4, %%TMP1
        adc     %%TMP2, 0
        
        mulx    %%TMP1, %%X5, [%%SRC2+8*6]
        add     %%X5, %%X6
        adc     %%TMP1, 0
        add     %%X5, %%TMP2
        adc     %%TMP1, 0
        
        mulx    %%TMP2, %%X6, [%%SRC2+8*7]
        add     %%X6, %%X7
        adc     %%TMP2, 0
        add     %%X6, %%TMP1
        adc     %%TMP2, 0

        mov     %%X7, %%TMP2

%endmacro


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This version of squaring using some inline code (provided by the
; SQR_1024 macro) coupled with some called functions (defined by the
; SUBS macro). There can be one or more invokations of SQR_1024, but there
; needs to be exactly one invocation of SUBS. 
; 
; The arguments to SQR_1024 and SUBS must be the same. This is to ensure
; that data will be passed properly between the inline code and the functions.

; Define subroutines needed for squaring macro. These subroutines are designed
; explicitly for use in squaring, and they may need to be tweaked in order to
; be used elsewhere.
; MACRO SUBS <args>
%macro SUBS 13
%define %%pDst  %1
%define %%pA    %2
%define %%A     %3
%define %%t0    %4
%define %%x7    %5
%define %%x6    %6
%define %%x5    %7
%define %%x4    %8
%define %%x3    %9
%define %%x2    %10
%define %%x1    %11
%define %%x0    %12
%define %%x8    %13
%define %%pB    %%x8

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Subroutine to perform two diagonals of multiplication or effectively a
; 128 bit by 512 bit multiplication
; in: partial product in {x7...x0}
;     8 qwords: pA
;     2 qwords: pB
; out: partial product in {x1 x0 x7 x6 ... x2} pDst[1,0]
; clobbers rdx, rax
mul_128_512:
        mov     rdx, [%%pB + 8*0]
        MULSTEP_512    %%x7, %%x6, %%x5, %%x4, %%x3, %%x2, %%x1, %%x0, [%%pDst + 8*0], %%pA, %%t0, %%A, rax

        mov     rdx, [%%pB + 8*1]
        MULSTEP_512    %%x7, %%x6, %%x5, %%x4, %%x3, %%x2, %%x1, %%x0, [%%pDst + 8*1], %%pA, %%t0, %%A, rax
        ret


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Subroutine to multiply "off-diagonal" terms of squaring 8 qwords of pA, i.e.
; pA[0] * pA[7...1]
; pA[1] * pA[7...2]
; ...
; pA[6] * pA[7]

; in: partial product in {x0 x7...x1}
;     8 qwords: pA
; out: partial product in {x7 ... x0} pDst[7...0]

sqr_448:
        mov             rdx, [%%pA + 8*0]
        MULSTEP_512_sq  %%x1, %%x0, %%x7, %%x6, %%x5, %%x4, %%x3, %%x2,    -, %%x1, [%%pDst+8*0], %%pA, %%t0, %%A

        mov             rdx, [%%pA + 8*1]
        MULSTEP_512_sq  %%x2, %%x1, %%x0, %%x7, %%x6, %%x5, %%x4,    -,    -, %%x2, [%%pDst+8*1], %%pA, %%t0, %%A

        mov             rdx, [%%pA + 8*2]
        MULSTEP_512_sq  %%x3, %%x2, %%x1, %%x0, %%x7, %%x6,    -,    -,    -, %%x3, [%%pDst+8*2], %%pA, %%t0, %%A

        mov             rdx, [%%pA + 8*3]
        MULSTEP_512_sq  %%x4, %%x3, %%x2, %%x1, %%x0,    -,    -,    -,    -, %%x4, [%%pDst+8*3], %%pA, %%t0, %%A

        mov             rdx, [%%pA + 8*4]
        MULSTEP_512_sq  %%x5, %%x4, %%x3, %%x2,    -,    -,    -,    -,    -, %%x5, [%%pDst+8*4], %%pA, %%t0, %%A

        mov             rdx, [%%pA + 8*5]
        MULSTEP_512_sq  %%x6, %%x5, %%x4,    -,    -,    -,    -,    -,    -, %%x6, [%%pDst+8*5], %%pA, %%t0, %%A
        
        mov             rdx, [%%pA + 8*6]
        MULSTEP_512_sq  %%x7, %%x6,    -,    -,    -,    -,    -,    -,    -, %%x7, [%%pDst+8*6], %%pA, %%t0, %%A
        ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; subroutine to square 4 qwords of pA and add it to twice pDst

; in: x8: carry-in
; out: x8: carry-out
diag_4:
        mov     %%x0, [%%pDst + 8*0]
        mov     %%x1, [%%pDst + 8*1]
        mov     %%x2, [%%pDst + 8*2]
        mov     %%x3, [%%pDst + 8*3]
        mov     %%x4, [%%pDst + 8*4]
        mov     %%x5, [%%pDst + 8*5]
        mov     %%x6, [%%pDst + 8*6]
        mov     %%x7, [%%pDst + 8*7]

        xor     %%t0, %%t0
        add     %%x0, %%x0
        adc     %%x1, %%x1
        adc     %%x2, %%x2
        adc     %%x3, %%x3
        adc     %%x4, %%x4
        adc     %%x5, %%x5
        adc     %%x6, %%x6
        adc     %%x7, %%x7
        adc     %%t0, 0

        mov     rdx, [%%pA + 8*0]
        mulx    rdx, rax, rdx
        add     rax, %%x8
        adc     rdx, 0
        mov     %%x8, %%t0
        add     %%x0, rax
        adc     %%x1, rdx

        mov     rdx, [%%pA + 8*1]
        mulx    rdx, rax, rdx
        adc     %%x2, rax
        adc     %%x3, rdx
        mov     [%%pDst + 8*0], %%x0
        mov     [%%pDst + 8*1], %%x1

        mov     rdx, [%%pA + 8*2]
        mulx    rdx, rax, rdx
        adc     %%x4, rax
        adc     %%x5, rdx
        mov     [%%pDst + 8*2], %%x2
        mov     [%%pDst + 8*3], %%x3

        mov     rdx, [%%pA + 8*3]
        mulx    rdx, rax, rdx
        adc     %%x6, rax
        adc     %%x7, rdx
        mov     [%%pDst + 8*4], %%x4
        mov     [%%pDst + 8*5], %%x5

        adc     %%x8, 0
        mov     [%%pDst + 8*6], %%x6
        mov     [%%pDst + 8*7], %%x7
        ret
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; MACRO to square a 1024 bit number
; MACRO SQR_1024 pDst, pA, A, t0, x7, ..., x0, tmp1, tmp2
; Input is in memory, pointed to by pA
; Output is in memory, pointed to by pDst
; Registers pDst and pA remain intact, the other 11 arguments and
; rax and rdx are clobbered
%macro SQR_1024 13
%define %%pDst  %1
%define %%pA    %2
%define %%A     %3
%define %%t0    %4
%define %%x7    %5
%define %%x6    %6
%define %%x5    %7
%define %%x4    %8
%define %%x3    %9
%define %%x2    %10
%define %%x1    %11
%define %%x0    %12
%define %%x8    %13
%define %%pB    %%x8
        xor     %%x0, %%x0
        xor     %%x1, %%x1
        xor     %%x2, %%x2
        xor     %%x3, %%x3
        xor     %%x4, %%x4
        xor     %%x5, %%x5
        xor     %%x6, %%x6
        xor     %%x7, %%x7

        call    sqr_448
        ; partial product in x7 x6 ... x1 x0

        mov     [%%pDst+8*7], %%x0

        mov     %%x0, %%x1
        mov     %%x1, %%x2
        mov     %%x2, %%x3
        mov     %%x3, %%x4
        mov     %%x4, %%x5
        mov     %%x5, %%x6
        mov     %%x6, %%x7
        xor     %%x7, %%x7

        mov     %%pB, %%pA
        add     %%pA, 8*8
        add     %%pDst, 8*8

%rep 3
        call    mul_128_512
        ; result in x1 x0 x7 x6 ... x3 x2

        add     %%pB,   8*2
        add     %%pDst, 8*2

%endrep

        call    mul_128_512
        ; result in x7 x6 ... x3 x2 x1 x0 
        

        mov     %%t0, %%x7
        mov     %%x7, %%x6
        mov     %%x6, %%x5
        mov     %%x5, %%x4
        mov     %%x4, %%x3
        mov     %%x3, %%x2
        mov     %%x2, %%x1
        mov     %%x1, %%x0
        mov     %%x0, %%t0

        add     %%pDst, 8*2

        call    sqr_448
        ; partial product in x7 x6 ... x1 x0

        sub     %%pA, 8*8
        sub     %%pDst, 8*16

        mov     [%%pDst+8*23], %%x0
        mov     [%%pDst+8*24], %%x1
        mov     [%%pDst+8*25], %%x2
        mov     [%%pDst+8*26], %%x3
        mov     [%%pDst+8*27], %%x4
        mov     [%%pDst+8*28], %%x5
        mov     [%%pDst+8*29], %%x6
        mov     [%%pDst+8*30], %%x7

        mov     qword [%%pDst+8*31], 0

        xor     %%x8, %%x8
        call    diag_4
        add     %%pDst, 8*8
        add     %%pA,   8*4
        call    diag_4
        add     %%pDst, 8*8
        add     %%pA,   8*4
        call    diag_4
        add     %%pDst, 8*8
        add     %%pA,   8*4
        call    diag_4

        sub     %%pA, 8*12
        sub     %%pDst, 8*24
%endmacro


;;;;;;;;;;;;;;;;
; Swizzle Macros
;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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





;;;;;;;;;;;;;;;;;
; Data Structures
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;
; Reduce Data
; temp space used to store intermediate results of the reduction operation
%define X1_offset       0               ; 8 qwords
%define X2_offset       X1_offset + 8*8 ; 8 qwords
%define X3_offset       X2_offset + 8*8 ; 8 qwords
%define Carries_offset  X3_offset + 8*8 ; 1 qword

; amount of total temp space
%define Red_Data_Size   Carries_offset + 1*8    ; (Total 25 qwords)

; pointers to the individual temp spaces allocated
%define pX1             Reduce_Data + X1_offset
%define pX2             Reduce_Data + X2_offset
%define pX3             Reduce_Data + X3_offset
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

;;;;;;;;;;;
; Functions
;;;;;;;;;;;

align 32
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; this multiplier is used in a D = A*B+C operation.
; D = destination: {r9, r8, r15, r14, r13, r12, r11, r10, rcx[ 8x8B ]} (high 8 qwords in registers, low 8 qwords in memory, total 16 qwords)
; A = src1: rdi[ 8x8B ]
; B = src2: rsi[ 8x8B ]
; C = {r15, r14, r13, r12, r11, r10, r9, r8}
; rdx, rax, rbp, rbx are clobbered
; rcx, rsi values are restored


_mul_512_512:
%rep 3
        call    mul_128_512
        add     rsi, 8*2
        add     rcx, 8*2
        
%endrep
        call    mul_128_512
        sub     rsi, 8*6
        sub     rcx, 8*6
ret

; dest: rcx [ 32x8B ]
; src1: rdi [ 16x8B ]
; src2: rsi [ 16x8B ]
; rdx, rax, rbp, rbx are clobbered
; rcx, rsi values are restored

_mul_1024_1024:
        xor     r8, r8
        xor     r9, r9
        xor     r10, r10
        xor     r11, r11
        xor     r12, r12
        xor     r13, r13
        xor     r14, r14
        xor     r15, r15
        call    _mul_512_512
        
        add     rcx, 8*8
        add     rsi, 8*8
        call    _mul_512_512
        mov     [rcx+8*8],r8
        mov     [rcx+8*9],r9
        mov     [rcx+8*10],r10
        mov     [rcx+8*11],r11
        mov     [rcx+8*12],r12
        mov     [rcx+8*13],r13
        mov     [rcx+8*14],r14
        mov     [rcx+8*15],r15
        
        mov     r8, [rcx+8*0]
        mov     r9, [rcx+8*1]
        mov     r10, [rcx+8*2]
        mov     r11, [rcx+8*3]
        mov     r12, [rcx+8*4]
        mov     r13, [rcx+8*5]
        mov     r14, [rcx+8*6]
        mov     r15, [rcx+8*7]
        
        add     rdi, 8*8
        sub     rsi, 8*8
        call    _mul_512_512
        xor     rbp, rbp

        op_reg_mem      add, r8, [rcx+8*8], rax
        op_reg_mem      adc, r9, [rcx+8*9], rax
        op_reg_mem      adc, r10, [rcx+8*10], rax
        op_reg_mem      adc, r11, [rcx+8*11], rax
        op_reg_mem      adc, r12, [rcx+8*12], rax
        op_reg_mem      adc, r13, [rcx+8*13], rax
        op_reg_mem      adc, r14, [rcx+8*14], rax
        op_reg_mem      adc, r15, [rcx+8*15], rax

        adc     rbp, 0
        push    rbp
        
        add     rcx, 8*8
        add     rsi, 8*8
        
        call    _mul_512_512
        sub     rcx, 8*16
        sub     rsi, 8*8
        sub     rdi, 8*8
        
        pop     rbp
        add     r8, rbp
        adc     r9, 0
        adc     r10, 0
        adc     r11, 0
        adc     r12, 0
        adc     r13, 0
        adc     r14, 0
        adc     r15, 0
        
        mov     [rcx+8*24],r8
        mov     [rcx+8*25],r9
        mov     [rcx+8*26],r10
        mov     [rcx+8*27],r11
        mov     [rcx+8*28],r12
        mov     [rcx+8*29],r13
        mov     [rcx+8*30],r14
        mov     [rcx+8*31],r15
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; mont_reduce(UINT64 *x,               // 2048 bits, 32 qwords
;;             MOD_EXP_1024_DATA *data,
;;             UINT64 *r)               //  1024 bits,  16 qwords
;;
;; Input:  x (number to be reduced): tmp32 (Implicit)
;;         data (reduce data):       [pData] (Implicit)
;; Output: r (result):               Address in [red_res_addr]
;; Do a Montgomery reduction of x (using data) and store the results in r. 


; 512x64 multiplication used by the reduction algorithm
; clobbers rax, rbp, rbx

mulstep_512_red:
        mulx    rbp, rax, [rdi+8*0]
        add     rax, r8
        adc     rbp, 0
        
        mulx    rbx, r8, [rdi+8*1]
        add     r8, r9
        adc     rbx, 0

        add     r8, rbp
        adc     rbx, 0
        
        mulx    rbp, r9, [rdi+8*2]
        add     r9, r10
        adc     rbp, 0

        add     r9, rbx
        adc     rbp, 0
        
        mulx    rbx, r10, [rdi+8*3]
        add     r10, r11
        adc     rbx, 0

        add     r10, rbp
        adc     rbx, 0
        
        mulx    rbp, r11, [rdi+8*4]
        add     r11, r12
        adc     rbp, 0

        add    r11, rbx
        adc     rbp, 0
        
        mulx    rbx, r12, [rdi+8*5]
        add     r12, r13
        adc     rbx, 0

        add     r12, rbp
        adc     rbx, 0
        
        mulx    rbp, r13, [rdi+8*6]
        add     r13, r14
        adc     rbp, 0

        add     r13, rbx
        adc     rbp, 0
        
        mulx    rbx, r14, [rdi+8*7]
        add     r14, r15
        adc     rbx, 0

        add     r14, rbp
        adc     rbx, 0

        mov     r15, rbx

ret


mont_reduce:
%define STACK_DEPTH 8*1

        mov     rsi, [pData + STACK_DEPTH]
        lea     rsi, [rsi + m_1]

        mov     rdi, rsi        ; M
        sub     rdi, (m_1 - M)

        mov     r8, [tmp32 + 8*0 + STACK_DEPTH]
        mov     r9, [tmp32 + 8*1 + STACK_DEPTH]
        mov     r10, [tmp32 + 8*2 + STACK_DEPTH]
        mov     r11, [tmp32 + 8*3 + STACK_DEPTH]
        mov     r12, [tmp32 + 8*4 + STACK_DEPTH]
        mov     r13, [tmp32 + 8*5 + STACK_DEPTH]
        mov     r14, [tmp32 + 8*6 + STACK_DEPTH]
        mov     r15, [tmp32 + 8*7 + STACK_DEPTH]

%assign red_counter 0
%rep 8

        mov     rdx, [rsi + 8*0]
        mulx    rbp, rdx, r8
        mov     [pX1 + 8*red_counter + STACK_DEPTH], rdx

        call    mulstep_512_red
        

        %assign red_counter (red_counter+1)
%endrep 
        
        xor     rcx, rcx
        add     r8, [tmp32 + 8*8 + STACK_DEPTH]
        adc     r9, [tmp32 + 8*9 + STACK_DEPTH]
        adc     r10, [tmp32 + 8*10 + STACK_DEPTH]
        adc     r11, [tmp32 + 8*11 + STACK_DEPTH]
        adc     r12, [tmp32 + 8*12 + STACK_DEPTH]
        adc     r13, [tmp32 + 8*13 + STACK_DEPTH]
        adc     r14, [tmp32 + 8*14 + STACK_DEPTH]
        adc     r15, [tmp32 + 8*15 + STACK_DEPTH]
        adc     rcx, 0


        add     rdi, 8*8
%assign red_counter 0
%rep 8
        mov     rdx, [pX1 + 8*red_counter + STACK_DEPTH]
        
        call    mulstep_512_red

        mov     [pX3 + 8*(red_counter) + STACK_DEPTH], rax


        %assign red_counter (red_counter+1)
%endrep 

        


        shr     rcx, 1
        adc     r8, [tmp32 + 8*16 + STACK_DEPTH]
        adc     r9, [tmp32 + 8*17 + STACK_DEPTH]
        adc     r10, [tmp32 + 8*18 + STACK_DEPTH]
        adc     r11, [tmp32 + 8*19 + STACK_DEPTH]
        adc     r12, [tmp32 + 8*20 + STACK_DEPTH]
        adc     r13, [tmp32 + 8*21 + STACK_DEPTH]
        adc     r14, [tmp32 + 8*22 + STACK_DEPTH]
        adc     r15, [tmp32 + 8*23 + STACK_DEPTH]
        adc     rcx, 0



        mov     [pX2 + 8*0 + STACK_DEPTH], r8
        mov     [pX2 + 8*1 + STACK_DEPTH], r9
        mov     [pX2 + 8*2 + STACK_DEPTH], r10
        mov     [pX2 + 8*3 + STACK_DEPTH], r11
        mov     [pX2 + 8*4 + STACK_DEPTH], r12
        mov     [pX2 + 8*5 + STACK_DEPTH], r13
        mov     [pX2 + 8*6 + STACK_DEPTH], r14
        mov     [pX2 + 8*7 + STACK_DEPTH], r15

        mov     r8, [pX3 + 8*0 + STACK_DEPTH]
        mov     r9, [pX3 + 8*1 + STACK_DEPTH]
        mov     r10, [pX3 + 8*2 + STACK_DEPTH]
        mov     r11, [pX3 + 8*3 + STACK_DEPTH]
        mov     r12, [pX3 + 8*4 + STACK_DEPTH]
        mov     r13, [pX3 + 8*5 + STACK_DEPTH]
        mov     r14, [pX3 + 8*6 + STACK_DEPTH]
        mov     r15, [pX3 + 8*7 + STACK_DEPTH]
        

        sub     rdi, 8*8

%assign red_counter 0
%rep 8
        
        mov     rdx, [rsi + 8*0]
        mulx    rbp, rdx, r8
        mov     [pX1 + 8*red_counter + STACK_DEPTH], rdx
        
        call    mulstep_512_red

        %assign red_counter (red_counter+1)
%endrep 
        

        add     r8, [pX2 + 8*0 + STACK_DEPTH]
        adc     r9, [pX2 + 8*1 + STACK_DEPTH]
        adc     r10, [pX2 + 8*2 + STACK_DEPTH]
        adc     r11, [pX2 + 8*3 + STACK_DEPTH]
        adc     r12, [pX2 + 8*4 + STACK_DEPTH]
        adc     r13, [pX2 + 8*5 + STACK_DEPTH]
        adc     r14, [pX2 + 8*6 + STACK_DEPTH]
        adc     r15, [pX2 + 8*7 + STACK_DEPTH]
        adc     rcx, 0


        add     rdi, 8*8

%assign red_counter 0
%rep 8
        
        mov     rdx, [pX1 + 8*red_counter + STACK_DEPTH]
        call    mulstep_512_red

        mov     [pX3 + 8*(red_counter) + STACK_DEPTH], rax


        %assign red_counter (red_counter+1)
%endrep 


        xor     rbx, rbx
        add     r8, [tmp32 + 8*24 + STACK_DEPTH]
        adc     r9, [tmp32 + 8*25 + STACK_DEPTH]
        adc     r10, [tmp32 + 8*26 + STACK_DEPTH]
        adc     r11, [tmp32 + 8*27 + STACK_DEPTH]
        adc     r12, [tmp32 + 8*28 + STACK_DEPTH]
        adc     r13, [tmp32 + 8*29 + STACK_DEPTH]
        adc     r14, [tmp32 + 8*30 + STACK_DEPTH]
        adc     r15, [tmp32 + 8*31 + STACK_DEPTH]
        adc     rbx, 0


        add     r8, rcx
        adc     r9, 0
        adc     r10, 0
        adc     r11, 0
        adc     r12, 0
        adc     r13, 0
        adc     r14, 0
        adc     r15, 0
        adc     rbx, 0

        mov     rcx, [red_res_addr  + STACK_DEPTH ]

        op_mem_mem      sub, [rcx+8*0], [pX3+STACK_DEPTH+8*0], [MZ + STACK_DEPTH + rbx*8 + 8*0], rax
        op_mem_mem      sbb, [rcx+8*1], [pX3+STACK_DEPTH+8*1], [MZ + STACK_DEPTH + rbx*8 + 8*2], rax
        op_mem_mem      sbb, [rcx+8*2], [pX3+STACK_DEPTH+8*2], [MZ + STACK_DEPTH + rbx*8 + 8*4], rax
        op_mem_mem      sbb, [rcx+8*3], [pX3+STACK_DEPTH+8*3], [MZ + STACK_DEPTH + rbx*8 + 8*6], rax
        op_mem_mem      sbb, [rcx+8*4], [pX3+STACK_DEPTH+8*4], [MZ + STACK_DEPTH + rbx*8 + 8*8], rax
        op_mem_mem      sbb, [rcx+8*5], [pX3+STACK_DEPTH+8*5], [MZ + STACK_DEPTH + rbx*8 + 8*10], rax
        op_mem_mem      sbb, [rcx+8*6], [pX3+STACK_DEPTH+8*6], [MZ + STACK_DEPTH + rbx*8 + 8*12], rax
        op_mem_mem      sbb, [rcx+8*7], [pX3+STACK_DEPTH+8*7], [MZ + STACK_DEPTH + rbx*8 + 8*14], rax
        op_mem_reg_mem  sbb, [rcx+8*8], r8, [MZ + STACK_DEPTH + rbx*8 + 8*16], rax
        op_mem_reg_mem  sbb, [rcx+8*9], r9, [MZ + STACK_DEPTH + rbx*8 + 8*18], rax
        op_mem_reg_mem  sbb, [rcx+8*10], r10, [MZ + STACK_DEPTH + rbx*8 + 8*20], rax
        op_mem_reg_mem  sbb, [rcx+8*11], r11, [MZ + STACK_DEPTH + rbx*8 + 8*22], rax
        op_mem_reg_mem  sbb, [rcx+8*12], r12, [MZ + STACK_DEPTH + rbx*8 + 8*24], rax
        op_mem_reg_mem  sbb, [rcx+8*13], r13, [MZ + STACK_DEPTH + rbx*8 + 8*26], rax
        op_mem_reg_mem  sbb, [rcx+8*14], r14, [MZ + STACK_DEPTH + rbx*8 + 8*28], rax
        op_mem_reg_mem  sbb, [rcx+8*15], r15, [MZ + STACK_DEPTH + rbx*8 + 8*30], rax


ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; mont_mul_1024 : subroutine to compute (Src1 * Src2) % M (all 1024-bits)
;; Input:  src1: Address of source 1: rdi
;;         src2: Address of source 2: rsi
;; Output: dst:  Address of destination: [red_res_addr]
;;    src2 and result also in: r9, r8, r15, r14, r13, r12, r11, r10
;; Temp:   Clobbers [tmp32], all registers

mont_mul_1024:
%define STACK_DEPTH 8
        ;;;;;;;;;;;;;;;;
        ; multiply tmp = src1 * src2
        ; For multiply: dst = rcx, src1 = rdi, src2 = rsi
        ; stack depth is extra 8 from call
        call    _mul_1024_1024

        ;;;;;;;;;;;;;;;;
        ; Dst = tmp % m
        ; Call reduce(tmp, data, dst)
        mov     rcx, [red_res_addr + STACK_DEPTH]
        
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce


;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; sqr_reduce : subroutine to compute Result = reduce(Result * Result)
;; Output: dst:  Address of destination: [red_res_addr]
;; Temp:   Clobbers [tmp32], all registers


sqr_reduce_1024:
%define STACK_DEPTH 8

        lea     rcx, [tmp32 + STACK_DEPTH]

        SQR_1024        rcx, rdi, rbp, rbx, r15, r14, r13, r12, r11, r10, r9, r8, rsi
        
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; MAIN FUNCTION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;void rsax_mod_exp_1024_mulx(
;       UINT64 *result, // 1024 bits, 16 qwords
;       UINT64 *g,      // 1024 bits, 16 qwords
;       UINT64 *exp,    // 1024 bits, 16 qwords
;       MOD_EXP_1024_DATA *data);
        
global rsax_mod_exp_1024_mulx
rsax_mod_exp_1024_mulx:

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
        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Copy exponent onto stack
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%assign j 0
%rep 16 
        mov     rax, [arg3 + 8*j]
        mov     [exp + 8*j], rax
%assign j (j+1)
%endrep
        xor     rax, rax
        mov     [exp + 8*j], rax
        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Interleave M with 0
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        mov     rsi, [pData]
        add     rsi, M

%assign j 0
%rep 16 
        mov     [MZ + 8*(2*j)], rax

        mov     rcx, [rsi + 8*j]
        mov     [MZ + 8*(2*j+1)], rcx
%assign j (j+1)
%endrep

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; R = 2^1024 mod m
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G0 = (g^0)*R = R  
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G1 = (g^1)*R = MM(R^2, g)   
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G2 = (g^2)*R = SQ(G1)      
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rax, [GT2]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*2
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G4 = (g^4)*R = SQ(G2)          
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rdi, [GT2]
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*4
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G8 = (g^8)*R = SQ(G4)          
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*8
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G16 = (g^16)*R = SQ(G8)        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*16
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G3 = (g^3)*R = MM(G2, G1)      
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G6 = (g^6)*R = SQ(G3)          
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*6
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G12 = (g^12)*R = SQ(G6)        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*12
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G24 = (g^24)*R = SQ(G12)       
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*24
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G5 = (g^5)*R = MM(G2, G3)      
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G10 = (g^10)*R = SQ(G5)        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*10
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G20 = (g^20)*R = SQ(G10)       
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*20
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G7 = (g^7)*R = MM(G2, G5)      
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G14 = (g^14)*R = SQ(G7)        
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*14
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G28 = (g^28)*R = SQ(G14)       
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rdi, [pResult]
        mov     [red_res_addr], rdi
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*28
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G9 = (g^9)*R = MM(G2, G7)      
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G18 = (g^18)*R = SQ(G9)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*18
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G11 = (g^11)*R = MM(G2, G9);
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G22 = (g^22)*R = SQ(G11)       
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*22
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G13 = (g^13)*R = MM(G2, G11);
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G26 = (g^26)*R = SQ(G13)       
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*26
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G15 = (g^15)*R = MM(G2, G13)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G30 = (g^30)*R = SQ(G15)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        mov     rax, [pResult]
        mov     [red_res_addr], rax
        call    sqr_reduce_1024

        lea     rsi, [garray]
        add     rsi, 2*30
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G17 = (g^17)*R = MM(G2, G15)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G19 = (g^19)*R = MM(G2, G17)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*19
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G21 = (g^21)*R = MM(G2, G19)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*21
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G23 = (g^23)*R = MM(G2, G21)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*23
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G25 = (g^25)*R = MM(G2, G23)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*25
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G27 = (g^27)*R = MM(G2, G25)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*27
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G29 = (g^29)*R = MM(G2, G27)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        mov     rdi, rcx
        lea     rsi, [garray]
        add     rsi, 2*29
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ; Compute G31 = (g^31)*R = MM(G2, G29)
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        lea     rcx, [tmp32]
        lea     rsi, [GT2]
        lea     rax, [GT]
        mov     [red_res_addr], rax
        call    mont_mul_1024
        
        lea     rsi, [garray]
        add     rsi, 2*31
        swizzle rsi, rcx, rax, rbx

        ;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;
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

        ;;;;;;;;;;;;;;;;
        ; Call mod_mul_a1(pDst,  pSrc1, pSrc2, pM, pData)
        ;                 result result pG     M   Data
        lea     rdi, [tmp16]
        lea     rcx, [tmp32]    
        
        mov     rsi, [pResult]
        call    mont_mul_1024

        ;;;;;;;;;;;;;;;;
        ; finish loop
        mov     rcx, [loop_idx]
        sub     rcx, 5
        mov     [loop_idx], rcx
        jge     main_loop

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;;;;;;;;;;;;;;;
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

        
        ;;;;;;;;;;;;;;;;
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

        
        ;;;;;;;;;;;;;;;;
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
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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

        
; set the registers to be used by the macros in SUBS. 
; the registers used in the SUBS macro instantiation must match those used in the SQR_1024 macro.
SUBS    rcx, rdi, rbp, rbx, r15, r14, r13, r12, r11, r10, r9, r8, rsi
