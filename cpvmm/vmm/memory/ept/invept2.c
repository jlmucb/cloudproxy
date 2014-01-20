void vmm_asm_invept (INVEPT_ARG *arg, UINT32 modifier, UINT64 *rflags)
{
     asm volatile(
        "\tmovq    %[arg], %%rax\n" \
        "\tmovq    %[modifier], %%rcx\n" \
        "\tmovq    %[rflags], %%r8\n" \
        "\tinvvpid  xmmword ptr (%rax), %%rcx\n" \
        "\tpushfq\n" \
        : 
        : [arg] "m" (arg), [modifier] "m" (modifier), [rflags] "m" (rflags),
        : "%rax", "%rcx", "%r8");
    // JLM: is the last push right?
}
