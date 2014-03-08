 #define __cpuid(__level, __eax, __ebx, __ecx, __edx) \
__asm("  pushl  %%ebx\n" \
"  cpuid\n" \
"  mov    %%ebx,%1\n" \
"  popl   %%ebx" \
: "=a"(__eax), "=r" (__ebx), "=c"(__ecx), "=d"(__edx) \
: "0"(__level))
