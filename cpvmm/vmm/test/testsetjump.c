#include "stdio.h"
#include "setjmp.h"

jmp_buf buf;


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
    if(setjmp(buf)==0)  {
        ProgramA();
    }
    else {
        printf("back at main\n");
    }
    return 0;
}
