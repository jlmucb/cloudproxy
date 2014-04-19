#include "stdio.h"
#include "setjmp.h"

jmp_buf buf;

extern int setjmp(jmp_buf);
extern void longjmp(jmp_buf, int);


void ProgramB()
{
    longjmp(buf,1);
}


void ProgramA()
{
    ProgramB();
    printf("Program A\n");
}


int main(int an, char**av)
{
    long long int bitset= 0x0005;
    unsigned      n= 1;
    unsigned*     bit_number_ptr= &n;

    asm volatile(
        "\tmovq	%[bit_number_ptr], %%rbx\n"
        "\tbsrq (%%rbx), %[bitset]\n"
    :
    :[bit_number_ptr] "p" (bit_number_ptr), 
     [bitset] "r" (bitset)
    : "%rbx");

    printf("Num: %016lx, bitnum: %d, bitptr: %016lx\n", 
	  bitset, n, bit_number_ptr);

    if(setjmp(buf)==0)  {
        ProgramA();
    }
    else {
        printf("back at main\n");
    }
    return 0;
}
