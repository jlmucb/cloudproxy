#include "stdio.h"


int xch(int* pmutex)
{
    int ret= 0;

    asm volatile (
        "\tmovq   $1, %%rax\n"
        "\tmovq   %[pmutex], %%rcx\n"
        "\txchgb  %%al, (%%rcx)\n"
        "\tmovl   %%eax, %[ret]\n"
    : [ret] "=g" (ret)
    : [pmutex] "p" (pmutex)
    : "%rax", "%rcx");

    return ret;
}


int main(int an, char** av)
{
    int  mutex= 0;
    int  ret= 0;

    ret= 0;
    printf("old mutex: %d, ", mutex);
    ret= xch(&mutex);
    printf("return: %d\n", ret);
    mutex= 1;
    printf("old mutex: %d, ", mutex);
    ret= xch(&mutex);
    printf("return: %d\n", ret);
    return 0;
}

