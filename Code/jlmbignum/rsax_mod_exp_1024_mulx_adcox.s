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
;
; constant-time modular exponentiation
; mod-exp 1024, with mulx, adcx, adox instructions
; single loop windowing code
; fixed windowing with window size of 5 bits
; YASM syntax, x64 instructions
; a version of the YASM supporting mulx, adcx, adox instructions is required. 
; 
; void rsax_mod_exp_1024_mulx_adcox(
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
; A version of word-level Montgomery Reduction algorithm is used with b = 2^64, n = 16, R = 2^1024, m' = -m^(-1) mod 2^64
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




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Define multiplication macros
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;
; Diagonal Macro
; 64x512  bit multiplication accumulated with 512-bit intermediate result
; 1 QW x 8 QW
; Source 1: %%OP register
; Source 2: %%SRC2
; Intermediate result: Registers %%X7:%%X0
; if %%if_store is not '-', result stored in %%X0, %%X7:%%X1, %%DST
; if %%if_store is '-', result stored in %%X0, %%X7:%%X1, lowest QW is discarded
; clobbers rax
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
%define %%T1    %11
%define %%T2    %12
%define %%T3    %13

        xor     %%T3, %%T3
        
        mulx    %%T1, %%T2, [%%SRC2+8*0]        ; TMP1:TMP2 = rdx * [%%SRC2+8*0]
        adox    %%X0, %%T2
        mov     %%DST, %%X0
        adcx    %%X1, %%T1
        
        mulx    %%T1, %%X0, [%%SRC2+8*1]        ; TMP1:X0 = rdx * [%%SRC2+8*1]
        adox    %%X0, %%X1
        adcx    %%X2, %%T1
        
        mulx    %%T1, %%X1, [%%SRC2+8*2]        ; TMP1:X1 = rdx * [%%SRC2+8*2]
        adox    %%X1, %%X2
        adcx    %%X3, %%T1
        
        mulx    %%T1, %%X2, [%%SRC2+8*3]        ; TMP1:X2 = rdx * [%%SRC2+8*3]
        adox    %%X2, %%X3
        adcx    %%X4, %%T1
        
        mulx    %%T1, %%X3, [%%SRC2+8*4]        ; TMP1:X3 = rdx * [%%SRC2+8*4]
        adox    %%X3, %%X4
        adcx    %%X5, %%T1
        
        mulx    %%T1, %%X4, [%%SRC2+8*5]        ; TMP1:X4 = rdx * [%%SRC2+8*5]
        adox    %%X4, %%X5
        adcx    %%X6, %%T1
        
        mulx    %%T1, %%X5, [%%SRC2+8*6]        ; TMP1:X5 = rdx * [%%SRC2+8*6]
        adox    %%X5, %%X6
        adcx    %%T1, %%X7
        
        mulx    %%X7, %%X6, [%%SRC2+8*7]        ; X7:X6 = rdx * [%%SRC2+8*7]
        adox    %%X6, %%T1

        adcx    %%X7, %%T3
        adox    %%X7, %%T3

%endmacro

; swap adcx chain with adox chain in MULSTEP_512 macro
%macro MULSTEP_512_alt 13
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
%define %%T1    %11
%define %%T2    %12
%define %%T3    %13

        xor     %%T3, %%T3
        
        mulx    %%T1, %%T2, [%%SRC2+8*0]        ; TMP1:TMP2 = rdx * [%%SRC2+8*0]
        adcx    %%X0, %%T2
        mov     %%DST, %%X0
        adox    %%X1, %%T1
        
        mulx    %%T1, %%X0, [%%SRC2+8*1]        ; TMP1:X0 = rdx * [%%SRC2+8*1]
        adcx    %%X0, %%X1
        adox    %%X2, %%T1
        
        mulx    %%T1, %%X1, [%%SRC2+8*2]        ; TMP1:X1 = rdx * [%%SRC2+8*2]
        adcx    %%X1, %%X2
        adox    %%X3, %%T1
        
        mulx    %%T1, %%X2, [%%SRC2+8*3]        ; TMP1:X2 = rdx * [%%SRC2+8*3]
        adcx    %%X2, %%X3
        adox    %%X4, %%T1
        
        mulx    %%T1, %%X3, [%%SRC2+8*4]        ; TMP1:X3 = rdx * [%%SRC2+8*4]
        adcx    %%X3, %%X4
        adox    %%X5, %%T1
        
        mulx    %%T1, %%X4, [%%SRC2+8*5]        ; TMP1:X4 = rdx * [%%SRC2+8*5]
        adcx    %%X4, %%X5
        adox    %%X6, %%T1
        
        mulx    %%T1, %%X5, [%%SRC2+8*6]        ; TMP1:X5 = rdx * [%%SRC2+8*6]
        adcx    %%X5, %%X6
        adox    %%T1, %%X7
        
        mulx    %%X7, %%X6, [%%SRC2+8*7]        ; X7:X6 = rdx * [%%SRC2+8*7]
        adcx    %%X6, %%T1

        adox    %%X7, %%T3
        adcx    %%X7, %%T3

%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Inputs: pDst: Destination  (1024 bits, 16 qwords)
;         pA:   Multiplicand (512 bits, 8 qwords)
;         pB:   Multiplicand (512 bits, 8 qwords)
; clobbers rax
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
%define %%T1    %12
%define %%T2    %13
%define %%first_mul     %14

%ifnidn %%first_mul, -
        mov     rdx, [%%pA+8*0]
        
        mulx    %%X0, rax, [%%pB+8*0]
        mov     [%%pDst + 8*0], rax
        
        mulx    %%X1, rax, [%%pB+8*1]
        add     %%X0, rax
        
        mulx    %%X2, rax, [%%pB+8*2]
        adc     %%X1, rax
        
        mulx    %%X3, rax, [%%pB+8*3]
        adc     %%X2, rax
        
        mulx    %%X4, rax, [%%pB+8*4]
        adc     %%X3, rax
        
        mulx    %%X5, rax, [%%pB+8*5]
        adc     %%X4, rax
        
        mulx    %%X6, rax, [%%pB+8*6]
        adc     %%X5, rax
        
        mulx    %%X7, rax, [%%pB+8*7]
        adc     %%X6, rax
        adc     %%X7, 0
%else
        mov     rdx, [%%pA+8*0]
        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*0], %%pB, %%T1, %%T2, rax
%endif
        mov     rdx, [%%pA+8*1]
        MULSTEP_512_alt %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*1], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*2]                                         
        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*2], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*3]                                         
        MULSTEP_512_alt %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*3], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*4]                                         
        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*4], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*5]                                         
        MULSTEP_512_alt %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*5], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*6]                                         
        MULSTEP_512     %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*6], %%pB, %%T1, %%T2, rax
        mov     rdx, [%%pA+8*7]                                         
        MULSTEP_512_alt %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, [%%pDst+8*7], %%pB, %%T1, %%T2, rax


%endmacro



; dest: rcx [ 32x8B ]
; src1: rdi [ 16x8B ]
; src2: rsi [ 16x8B ]
; rbp, rbx: temp registers
; rcx, rsi values are restored
; clobbers rax
%macro MUL_1024_1024 13
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
        
        MUL_512x512 %%pDst, %%pA, %%pB, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, first_mul

        MUL_512x512 %%pDst+8*8, %%pA, %%pB+8*8, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
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

        MUL_512x512 %%pDst+8*8, %%pA+8*8, %%pB, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
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
        
        MUL_512x512 %%pDst+8*16, %%pA+8*8, %%pB+8*8, %%X7, %%X6, %%X5, %%X4, %%X3, %%X2, %%X1, %%X0, %%T1, %%T2, -
        
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


; SQR_1024: Square a 1024-bit number
; rax is clobbered
%macro SQR_1024 14
%define %%pDst  %1
%define %%pA    %2
%define %%pB    %3
%define %%x7    %4
%define %%x6    %5
%define %%x5    %6
%define %%x4    %7
%define %%x3    %8
%define %%x2    %9
%define %%x1    %10
%define %%x0    %11
%define %%T1    %12
%define %%T2    %13
%define %%temp_mem      %14
%define %%T3    %%x0
;;;;;;;;;;
; diag 0_1
;;;;;;;;;;
        xor     %%T2, %%T2
        

        mov     rdx, [%%pA + 8*13]
        mulx    %%x4, %%x3, [%%pA + 8*2]


        
        
        
        mov     rdx, [%%pA + 8*0]
        
        mulx    %%x0, %%T1, [%%pA + 8*11]
        mov     [%%temp_mem + 8*1], %%T1
        

        mulx    %%x1, %%T1, [%%pA + 8*12]
        adcx    %%x0, %%T1
        
        mov     [%%temp_mem + 8*2], %%x0
        
        mulx    %%x2, %%T3, [%%pA + 8*13]
        adcx    %%x1, %%T3

        
        mulx    %%T1, %%T3, [%%pA + 8*14]
        adcx    %%x2, %%T3
        adox    %%x3, %%T1
        
        mov     rdx, [%%pA + 8*15]
        mulx    %%T1, %%T3, [%%pA + 8*0]
        adcx    %%x3, %%T3
        adox    %%x4, %%T1
        
        mulx    %%x5, %%T3, [%%pA + 8*1]
        adcx    %%x4, %%T3
        
        mulx    %%x6, %%T3, [%%pA + 8*2]
        adcx    %%x5, %%T3
        adox    %%x5, %%T2
        
        mulx    %%x7, %%T3, [%%pA + 8*3]
        adcx    %%x6, %%T3
        adox    %%x6, %%T2
        
        mulx    %%x0, %%T1, [%%pA + 8*4]
        adcx    %%x7, %%T1
        adox    %%x7, %%T2
        
        adcx    %%x0, %%T2
        adox    %%x0, %%T2
        
        
        

;;;;;;;;;;;
;; diag 0_2
;;;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*1]
        
        mulx    %%T1, rax, [%%pA + 8*12]
        adcx    %%x1, rax
        mov     [%%temp_mem + 8*3], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*13]
        adcx    %%x2, rax
        mov     [%%temp_mem + 8*4], %%x2
        adox    %%x3, %%T1
        
        mov     rdx, [%%pA + 8*14]
        mulx    %%T1, rax, [%%pA + 8*1]
        adcx    %%x3, rax
        mov     [%%temp_mem + 8*5], %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*2]
        adcx    %%x4, rax
        mov     [%%temp_mem + 8*6], %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*3]
        adcx    %%x5, rax
        mov     [%%temp_mem + 8*7], %%x5
        adox    %%x6, %%T1
        
        adcx    %%x6, %%T2
        mov     [%%temp_mem + 8*8], %%x6
        adox    %%x7, %%T2
        
        adcx    %%x7, %%T2
        mov     [%%temp_mem + 8*9], %%x7
        adox    %%x0, %%T2
        
        adcx    %%x0, %%T2
        mov     [%%temp_mem + 8*10], %%x0
        

        
;;;;;;;;;
;; diag 1
;;;;;;;;;

        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*0]
        
        mulx    %%T1, %%x7, [%%pA + 8*1]
        mov     [%%pDst + 8*1], %%x7
        
        mulx    %%x0, %%x7, [%%pA + 8*2]
        adcx    %%T1, %%x7
        
        mov     [%%pDst + 8*2], %%T1
        
        mulx    %%x1, %%T1, [%%pA + 8*3]
        adcx    %%x0, %%T1
        
        mulx    %%x2, %%T1, [%%pA + 8*4]
        adcx    %%x1, %%T1
        
        mulx    %%x3, %%T1, [%%pA + 8*5]
        adcx    %%x2, %%T1
        
        mulx    %%x4, %%T1, [%%pA + 8*6]
        adcx    %%x3, %%T1
        
        mulx    %%x5, %%T1, [%%pA + 8*7]
        adcx    %%x4, %%T1
        
        mulx    %%x6, %%T1, [%%pA + 8*8]
        adcx    %%x5, %%T1
        
        mulx    %%x7, %%T1, [%%pA + 8*9]
        adcx    %%x6, %%T1
        
        mulx    rax, %%T1, [%%pA + 8*10]
        adcx    %%x7, %%T1
        adcx    rax, %%T2

;;;;;;;;;
;; diag 2
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*1]
        
        mulx    %%T1, %%T2, [%%pA + 8*2]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*3], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*3]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*4], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*4]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*5]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*6]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*7]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*8]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%T1, %%x5, [%%pA + 8*9]
        adcx    %%x5, %%x7
        adox    rax, %%T1
        
        mulx    %%x7, %%x6, [%%pA + 8*10]
        adcx    %%x6, rax
        adox    %%x7, [%%temp_mem + 8*2]
        
        mulx    rax, %%T1, [%%pA + 8*11]
        adcx    %%x7, %%T1
        
        mov     %%T2, 0
        
        adcx    rax, %%T2
        adox    rax, %%T2
        
;;;;;;;;;
;; diag 3
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*2]
        
        mulx    %%T1, %%T2, [%%pA + 8*3]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*5], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*4]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*6], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*5]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*6]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*7]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*8]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*9]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%T1, %%x5, [%%pA + 8*10]
        adcx    %%x5, %%x7
        adox    rax, %%T1
        
        mulx    %%x7, %%x6, [%%pA + 8*11]
        adcx    %%x6, rax
        adox    %%x7, [%%temp_mem + 8*4]
        
        mulx    rax, %%T1, [%%pA + 8*12]
        adcx    %%x7, %%T1
        
        mov     %%T2, 0
        
        adcx    rax, %%T2
        adox    rax, %%T2


;;;;;;;;;
;; diag 4
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*3]
        
        mulx    %%T1, %%T2, [%%pA + 8*4]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*7], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*5]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*8], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*6]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*7]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*8]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*9]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*10]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        
        
        mulx    %%T1, %%x5, [%%pA + 8*11]
        adcx    %%x5, %%x7
        adox    rax, %%T1
        
        mulx    %%x7, %%x6, [%%pA + 8*12]
        adcx    %%x6, rax
        adox    %%x7, [%%temp_mem + 8*6]
        
        mulx    rax, %%T1, [%%pA + 8*13]
        adcx    %%x7, %%T1
        
        mov     %%T2, 0
        
        adcx    rax, %%T2
        adox    rax, %%T2
        
        

;;;;;;;;;
;; diag 5
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*4]
        
        mulx    %%T1, %%T2, [%%pA + 8*5]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*9], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*6]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*10], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*7]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*8]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*9]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*10]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*11]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%T1, %%x5, [%%pA + 8*12]
        adcx    %%x5, %%x7
        adox    rax, %%T1
        
        mulx    %%x7, %%x6, [%%pA + 8*13]
        adcx    %%x6, rax
        adox    %%x7, [%%temp_mem + 8*8]
        
        mulx    rax, %%T1, [%%pA + 8*14]
        adcx    %%x7, %%T1
        
        mov     %%T2, 0
        
        adcx    rax, %%T2
        adox    rax, %%T2
        

;;;;;;;;;
;; diag 6
;;;;;;;;;

        xor     %%T2, %%T2
        adox    %%x0, [%%temp_mem + 8*1]
        
        mov     rdx, [%%pA + 8*5]
        
        mulx    %%T1, %%T2, [%%pA + 8*6]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*11], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*7]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*12], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*8]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*9]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*10]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*11]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*12]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%T1, %%x5, [%%pA + 8*13]
        adcx    %%x5, %%x7
        adox    rax, %%T1
        
        mulx    %%x7, %%x6, [%%pA + 8*14]
        adcx    %%x6, rax
        adox    %%x7, [%%temp_mem + 8*10]
        
        mulx    rax, %%T1, [%%pA + 8*15]
        adcx    %%x7, %%T1
        
        mov     %%T2, 0
        
        adcx    rax, %%T2
        adox    rax, %%T2
        

;;;;;;;;;
;; diag 7
;;;;;;;;;

        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*6]
        
        adox    %%x0, [%%temp_mem + 8*3]
        
        mulx    %%T1, %%T2, [%%pA + 8*7]
        adcx    %%x0, %%T2
        mov     [%%pDst + 8*13], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, %%T2, [%%pA + 8*8]
        adcx    %%x1, %%T2
        mov     [%%pDst + 8*14], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*9]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*10]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*11]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*12]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*13]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%x6, %%x5, [%%pA + 8*14]
        adcx    %%x5, %%x7
        adox    %%x6, rax
        
        mulx    %%x7, rax, [%%pA + 8*15]
        adcx    %%x6, rax
        
        mov     %%T2, 0
        adcx    %%x7, %%T2
        
        adox    %%x7, %%T2                      


;;;;;;;;;
;; diag 8
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*7]
        
        adox    %%x0, [%%temp_mem + 8*5]
        
        mulx    %%T1, rax, [%%pA + 8*8]
        adcx    %%x0, rax
        mov     [%%pDst + 8*15], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*9]
        adcx    %%x1, rax
        mov     [%%pDst + 8*16], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*10]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*11]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*12]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*13]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*14]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%x6, %%x5, [%%pA + 8*15]
        adcx    %%x5, %%x7
        
        mov     rdx, [%%pA + 8*12]
        mulx    %%x7, rax, [%%pA + 8*11]
        adcx    %%x6, rax
        
        adcx    %%x7, %%T2
        adox    %%x6, %%T2
        adox    %%x7, %%T2


;;;;;;;;;
;; diag 9
;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*8]

        adox    %%x0, [%%temp_mem + 8*7]
        
        mulx    %%T1, rax, [%%pA + 8*9]
        adcx    %%x0, rax
        mov     [%%pDst + 8*17], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*10]
        adcx    %%x1, rax
        mov     [%%pDst + 8*18], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*11]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*12]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*13]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*14]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*15]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mov     rdx, [%%pA + 8*13]
        mulx    %%x6, %%x5, [%%pA + 8*11]
        adcx    %%x5, %%x7
        
        mulx    %%x7, rax, [%%pA + 8*12]
        adcx    %%x6, rax
        
        adcx    %%x7, %%T2
        adox    %%x6, %%T2
        adox    %%x7, %%T2


;;;;;;;;;;
;; diag 10
;;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*9]
        
        adox    %%x0, [%%temp_mem + 8*9]
        
        mulx    %%T1, rax, [%%pA + 8*10]
        adcx    %%x0, rax
        mov     [%%pDst + 8*19], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*11]
        adcx    %%x1, rax
        mov     [%%pDst + 8*20], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*12]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*13]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1
        
        mulx    %%T1, %%x2, [%%pA + 8*14]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*15]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mov     rdx, [%%pA + 8*14]
        mulx    %%T1, %%x4, [%%pA + 8*11]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%x6, %%x5, [%%pA + 8*12]
        adcx    %%x5, %%x7
        
        mulx    %%x7, rax, [%%pA + 8*13]
        adcx    %%x6, rax
        
        adcx    %%x7, %%T2
        adox    %%x6, %%T2
        adox    %%x7, %%T2


;;;;;;;;;;
;; diag 11
;;;;;;;;;;
        xor     %%T2, %%T2
        mov     rdx, [%%pA + 8*10]
        
        mulx    %%T1, rax, [%%pA + 8*11]
        adcx    %%x0, rax
        mov     [%%pDst + 8*21], %%x0
        adox    %%x1, %%T1
        
        mulx    %%T1, rax, [%%pA + 8*12]
        adcx    %%x1, rax
        mov     [%%pDst + 8*22], %%x1
        adox    %%x2, %%T1
        
        mulx    %%T1, %%x0, [%%pA + 8*13]
        adcx    %%x0, %%x2
        adox    %%x3, %%T1
        
        mulx    %%T1, %%x1, [%%pA + 8*14]
        adcx    %%x1, %%x3
        adox    %%x4, %%T1

        mov     rdx, [%%pA + 8*15]
        
        mulx    %%T1, %%x2, [%%pA + 8*10]
        adcx    %%x2, %%x4
        adox    %%x5, %%T1
        
        mulx    %%T1, %%x3, [%%pA + 8*11]
        adcx    %%x3, %%x5
        adox    %%x6, %%T1
        
        mulx    %%T1, %%x4, [%%pA + 8*12]
        adcx    %%x4, %%x6
        adox    %%x7, %%T1
        
        mulx    %%x6, %%x5, [%%pA + 8*13]
        adcx    %%x5, %%x7
        
        mulx    %%x7, rax, [%%pA + 8*14]
        adcx    %%x6, rax
        
        adcx    %%x7, %%T2
        adox    %%x6, %%T2
        adox    %%x7, %%T2
        



;;;;;;;;;;;
;; finalize
;;;;;;;;;;;
        xor     rax, rax
        
        mov     rdx, [%%pA + 8*0]
        mulx    %%T1, rax, rdx
        mov     [%%pDst + 8*0], rax
        

        adcx    %%T1, [%%pDst + 8*1]
        adox    %%T1, [%%pDst + 8*1]
        mov     [%%pDst + 8*1], %%T1
        
%assign %%i 1
%rep 10
        mov     rdx, [%%pA + 8*%%i]
        mulx    %%T1, rax, rdx
        
        adcx    rax, [%%pDst + 8*(2*%%i)]
        adox    rax, [%%pDst + 8*(2*%%i)]
        mov     [%%pDst + 8*(2*%%i)], rax
        
        adcx    %%T1, [%%pDst + 8*(2*%%i + 1)]
        adox    %%T1, [%%pDst + 8*(2*%%i + 1)]
        mov     [%%pDst + 8*(2*%%i + 1)], %%T1
        %assign %%i %%i+1
%endrep 

        mov     rdx, [%%pA + 8*11]
        mulx    %%T1, rax, rdx
        
        adcx    rax, [%%pDst + 8*22]
        adox    rax, [%%pDst + 8*22]
        mov     [%%pDst + 8*22], rax
        
        adcx    %%T1, %%x0
        adox    %%T1, %%x0
        mov     [%%pDst + 8*23], %%T1
        
        
        mov     rdx, [%%pA + 8*12]
        mulx    %%T1, rax, rdx
        
        adcx    rax, %%x1
        adox    rax, %%x1
        mov     [%%pDst + 8*24], rax
        
        adcx    %%T1, %%x2
        adox    %%T1, %%x2
        mov     [%%pDst + 8*25], %%T1
        
        
        mov     rdx, [%%pA + 8*13]
        mulx    %%T1, rax, rdx
        
        adcx    rax, %%x3
        adox    rax, %%x3
        mov     [%%pDst + 8*26], rax
        
        adcx    %%T1, %%x4
        adox    %%T1, %%x4
        mov     [%%pDst + 8*27], %%T1
        
        
        mov     rdx, [%%pA + 8*14]
        mulx    %%T1, rax, rdx
        
        adcx    rax, %%x5
        adox    rax, %%x5
        mov     [%%pDst + 8*28], rax
        
        adcx    %%T1, %%x6
        adox    %%T1, %%x6
        mov     [%%pDst + 8*29], %%T1
        
        

        mov     rdx, [%%pA + 8*15]
        mulx    %%T1, rax, rdx
        
        adcx    rax, %%x7
        adox    rax, %%x7
        mov     [%%pDst + 8*30], rax
        
        mov     rax, 0
        adcx    %%T1, rax
        adox    %%T1, rax
        mov     [%%pDst + 8*31], %%T1
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


; struct MOD_EXP_1024_DATA {
;       UINT64 R[16];   // 2^1024 % m
;       UINT64 R2[16];  // 2^2048 % m
;       UINT64 M[16];   // m
;       UINT64 m_1[1];  // (-1/m) % 2^64

%define R       0
%define R2      128     ; = 8 * 8 * 2
%define M       256     ; = 8 * 8 * 4   //      += 8 * 8 * 2
%define m_1     384     ; = 8 * 8 * 6   //      += 8 * 8 * 2


;;;;;;;;;;;
; Functions
;;;;;;;;;;;

align 32

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; mont_reduce(UINT64 *x,               // 2048 bits, 32 qwords
;;             MOD_EXP_1024_DATA *data,
;;             UINT64 *r)               //  1024 bits,  16 qwords
;;
;; Input:  x (number to be reduced): tmp32 (Implicit)
;;         data (reduce data):       [pData] (Implicit)
;; Output: r (result):               Address in [red_res_addr]
;; Do a Montgomery reduction of x (using data) and store the results in r. 

mont_reduce:
%define STACK_DEPTH 8*1

        mov     rsi, [pData + STACK_DEPTH]
        lea     rsi, [rsi + m_1]

        mov     rdi, rsi        ; M
        sub     rdi, (m_1 - M)

        mov     rcx, [red_res_addr  + STACK_DEPTH ]

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
        xor     rax, rax
        
        mov     rdx, [rsi + 8*0]
        mulx    rbp, rdx, r8
        mov     [pX1 + 8*red_counter + STACK_DEPTH], rdx
        
        mulx    rbp, rbx, [rdi+8*0]
        adox    r8, rbx
        adcx    r9, rbp
        
        mulx    rbp, r8, [rdi+8*1]
        adox    r8, r9
        adcx    r10, rbp
        
        mulx    rbp, r9, [rdi+8*2]
        adox    r9, r10
        adcx    r11, rbp
        
        mulx    rbp, r10, [rdi+8*3]
        adox    r10, r11
        adcx    r12, rbp
        
        mulx    rbp, r11, [rdi+8*4]
        adox    r11, r12
        adcx    r13, rbp
        
        mulx    rbp, r12, [rdi+8*5]
        adox    r12, r13
        adcx    r14, rbp
        
        mulx    rbp, r13, [rdi+8*6]
        adox    r13, r14
        adcx    rbp, r15
        
        mulx    r15, r14, [rdi+8*7]
        adox    r14, rbp

        adcx    r15, rax
        adox    r15, rax

        %assign red_counter (red_counter+1)
%endrep 


%assign red_counter 0
%rep 8
        xor     rax, rax
        
        mov     rdx, [pX1 + 8*red_counter + STACK_DEPTH]

        mulx    rbp, rbx, [rdi+8*8]
        adox    rbx, r8
        adcx    r9, rbp
        
        mulx    rbp, r8, [rdi+8*9]
        adox    r8, r9
        adcx    r10, rbp
        
        mulx    rbp, r9, [rdi+8*10]
        adox    r9, r10
        adcx    r11, rbp
        
        mulx    rbp, r10, [rdi+8*11]
        adox    r10, r11
        adcx    r12, rbp
        
        mulx    rbp, r11, [rdi+8*12]
        adox    r11, r12
        adcx    r13, rbp
        
        mulx    rbp, r12, [rdi+8*13]
        adox    r12, r13
        adcx    r14, rbp
        
        mulx    rbp, r13, [rdi+8*14]
        adox    r13, r14
        adcx    rbp, r15
        
        mulx    r15, r14, [rdi+8*15]
        adox    r14, rbp
        mov     [rcx + 8*(red_counter+8)], rbx

        adcx    r15, rax
        adox    r15, rax

        %assign red_counter (red_counter+1)
%endrep 

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


%assign red_counter 0
%rep 8
        xor     rax, rax
        
        mov     rdx, [rsi + 8*0]
        mulx    rbp, rdx, r8
        mov     [pX1 + 8*red_counter + STACK_DEPTH], rdx
        
        mulx    rbp, rbx, [rdi+8*0]
        adox    r8, rbx
        adcx    r9, rbp
        
        mulx    rbp, r8, [rdi+8*1]
        adox    r8, r9
        adcx    r10, rbp
        
        mulx    rbp, r9, [rdi+8*2]
        adox    r9, r10
        adcx    r11, rbp
        
        mulx    rbp, r10, [rdi+8*3]
        adox    r10, r11
        adcx    r12, rbp
        
        mulx    rbp, r11, [rdi+8*4]
        adox    r11, r12
        adcx    r13, rbp
        
        mulx    rbp, r12, [rdi+8*5]
        adox    r12, r13
        adcx    r14, rbp
        
        mulx    rbp, r13, [rdi+8*6]
        adox    r13, r14
        adcx    rbp, r15
        
        mulx    r15, r14, [rdi+8*7]
        adox    r14, rbp

        adcx    r15, rax
        adox    r15, rax

        %assign red_counter (red_counter+1)
%endrep 


%assign red_counter 0
%rep 8
        xor     rax, rax
        
        mov     rdx, [pX1 + 8*red_counter + STACK_DEPTH]

        mulx    rbp, rbx, [rdi+8*8]
        adox    rbx, r8
        adcx    r9, rbp
        
        mulx    rbp, r8, [rdi+8*9]
        adox    r8, r9
        adcx    r10, rbp
        
        mulx    rbp, r9, [rdi+8*10]
        adox    r9, r10
        adcx    r11, rbp
        
        mulx    rbp, r10, [rdi+8*11]
        adox    r10, r11
        adcx    r12, rbp
        
        mulx    rbp, r11, [rdi+8*12]
        adox    r11, r12
        adcx    r13, rbp
        
        mulx    rbp, r12, [rdi+8*13]
        adox    r12, r13
        adcx    r14, rbp
        
        mulx    rbp, r13, [rdi+8*14]
        adox    r13, r14
        adcx    rbp, r15
        
        mulx    r15, r14, [rdi+8*15]
        adox    r14, rbp
        mov     [rcx + 8*(red_counter)], rbx

        adcx    r15, rax
        adox    r15, rax

        %assign red_counter (red_counter+1)
%endrep 
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

        adcx    r8, [rcx + 8*0]
        adox    r8, [tmp32 + 8*16 + STACK_DEPTH]
        mov     [rcx + 8*0], r8

        adcx    r9, [rcx + 8*1]
        adox    r9, [tmp32 + 8*17 + STACK_DEPTH]
        mov     [rcx + 8*1], r9

        adcx    r10, [rcx + 8*2]
        adox    r10, [tmp32 + 8*18 + STACK_DEPTH]
        mov     [rcx + 8*2], r10

        adcx    r11, [rcx + 8*3]
        adox    r11, [tmp32 + 8*19 + STACK_DEPTH]
        mov     [rcx + 8*3], r11

        adcx    r12, [rcx + 8*4]
        adox    r12, [tmp32 + 8*20 + STACK_DEPTH]
        mov     [rcx + 8*4], r12

        adcx    r13, [rcx + 8*5]
        adox    r13, [tmp32 + 8*21 + STACK_DEPTH]
        mov     [rcx + 8*5], r13

        adcx    r14, [rcx + 8*6]
        adox    r14, [tmp32 + 8*22 + STACK_DEPTH]
        mov     [rcx + 8*6], r14

        adcx    r15, [rcx + 8*7]
        adox    r15, [tmp32 + 8*23 + STACK_DEPTH]
        mov     [rcx + 8*7], r15
        

        mov     r8, [tmp32 + STACK_DEPTH + 8*24]
        adcx    r8, rax
        adox    r8, [rcx + 8*8]


        mov     r9, [tmp32 + STACK_DEPTH + 8*25]
        adcx    r9, rax
        adox    r9, [rcx + 8*9]


        mov     r10, [tmp32 + STACK_DEPTH + 8*26]
        adcx    r10, rax
        adox    r10, [rcx + 8*10]


        mov     r11, [tmp32 + STACK_DEPTH + 8*27]
        adcx    r11, rax
        adox    r11, [rcx + 8*11]


        mov     r12, [tmp32 + STACK_DEPTH + 8*28]
        adcx    r12, rax
        adox    r12, [rcx + 8*12]

        mov     r13, [tmp32 + STACK_DEPTH + 8*29]
        adcx    r13, rax
        adox    r13, [rcx + 8*13]


        mov     r14, [tmp32 + STACK_DEPTH + 8*30]
        adcx    r14, rax
        adox    r14, [rcx + 8*14]


        mov     r15, [tmp32 + STACK_DEPTH + 8*31]
        adcx    r15, rax
        adox    r15, [rcx + 8*15]


        adcx    rbx, rax
        adox    rbx, rax


        op_mem_mem      sub, [rcx+8*0], [rcx+8*0], [MZ + STACK_DEPTH + rbx*8 + 8*0], rax
        op_mem_mem      sbb, [rcx+8*1], [rcx+8*1], [MZ + STACK_DEPTH + rbx*8 + 8*2], rax
        op_mem_mem      sbb, [rcx+8*2], [rcx+8*2], [MZ + STACK_DEPTH + rbx*8 + 8*4], rax
        op_mem_mem      sbb, [rcx+8*3], [rcx+8*3], [MZ + STACK_DEPTH + rbx*8 + 8*6], rax
        op_mem_mem      sbb, [rcx+8*4], [rcx+8*4], [MZ + STACK_DEPTH + rbx*8 + 8*8], rax
        op_mem_mem      sbb, [rcx+8*5], [rcx+8*5], [MZ + STACK_DEPTH + rbx*8 + 8*10], rax
        op_mem_mem      sbb, [rcx+8*6], [rcx+8*6], [MZ + STACK_DEPTH + rbx*8 + 8*12], rax
        op_mem_mem      sbb, [rcx+8*7], [rcx+8*7], [MZ + STACK_DEPTH + rbx*8 + 8*14], rax
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
%define STACK_DEPTH 8*1
        ;;;;;;;;;;;;;;;;
        ; multiply tmp = src1 * src2
        ; For multiply: dst = rcx, src1 = rdi, src2 = rsi
        MUL_1024_1024   rcx, rdi, rsi, r15, r14, r13, r12, r11, r10, r9, r8, rbp, rbx

        ;;;;;;;;;;;;;;;;
        ; Dst = tmp % m
        ; Call reduce(tmp, data, dst)
        mov     rcx, [red_res_addr + STACK_DEPTH]
        
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce



;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; sqr_reduce : subroutine to compute Result = reduce(Result * Result)
;; Output: dst:  Address of destination: [red_res_addr]
;; Temp:   Clobbers [tmp32], all registers


sqr_reduce_1024:
%define STACK_DEPTH 8

        lea     rcx, [tmp32 + STACK_DEPTH]

        SQR_1024        rcx, rdi, rsi, r15, r14, r13, r12, r11, r10, r9, r8, rbp, rbx, tmp16 + STACK_DEPTH
        
        
        ;; tail recursion optimization: jmp to mont_reduce and return from there
        jmp     mont_reduce




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; MAIN FUNCTION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; void rsax_mod_exp_1024_mulx_adcox(
;       UINT64 *result, // 1024 bits, 16 qwords
;       UINT64 *g,      // 1024 bits, 16 qwords
;       UINT64 *exp,    // 1024 bits, 16 qwords
;       MOD_EXP_1024_DATA *data);

global rsax_mod_exp_1024_mulx_adcox
rsax_mod_exp_1024_mulx_adcox:

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
