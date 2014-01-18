void vmm_asm_invept (INVEPT_ARG *arg, UINT32 modifier, UINT64 *rflags)
{
     asm volatile(
        "\tmovq    %[arg], %%rax\n" \
        "\tmovq    %[modifier], %%rcx\n" \
        "\tinvvpid  xmmword ptr (eax), %%ecx\n" \
        "\tpushfq\n" \
        "\tpop      (%%r8)\n" \
        "\tret\n"
        : 
        : [arg] "m" (arg), [modifier] "m" (modifier), [rflags] "m" (rflags),
        : "%rax", "%rcx", "%r8");
}
