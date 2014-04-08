#include "stdio.h"


int main(int an, char** av)
{
    int i;
    long long int array[10]= {
        1,2,3,4,5,6,7,8,9,10
    };
    long long int* ptr1;
    long long int* ptr2;
    long long int* ptr3;

    asm volatile (
    "\tmovq     %[array], %%rsi\n"
    "\tmovq     $1, %%rdx\n"
    "\tleaq     (%%rsi, %%rdx, 8), %%rdi\n"
    "\tmovq     %%rdi,%[ptr1]\n"
    "\tmovq     $3, %%rdx\n"
    "\tleaq     (%%rsi, %%rdx, 8), %%rdi\n"
    "\tmovq     %%rdi,%[ptr2]\n"
    "\tmovq     $6, %%rdx\n"
    "\tleaq     (%%rsi, %%rdx, 8), %%rdi\n"
    "\tmovq     %%rdi,%[ptr3]\n"
    : [ptr1] "=m" (ptr1), [ptr2] "=m" (ptr2), [ptr3] "=m" (ptr3)
    : [array] "g" (array)
    : "%rdi", "%rsi", "%rdx");

    printf("ptr1: 0x%08x, ptr2: 0x%08x, ptr3: 0x%08x\n",
            (unsigned int)*ptr1, (unsigned int)*ptr2, (unsigned int)*ptr3);

    return 0;
}

