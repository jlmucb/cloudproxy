#
grep -n -H ".globl" ./common/libc/em64t/em64t_mem.s
grep -n -H ".globl" ./common/libc/ia32/ia32_mem.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_fpu.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_gcpu_regs_save_restore.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_interlocked.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_isr.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_setjmp.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_utils.s
grep -n -H ".globl" ./vmm/host/hw/em64t/em64t_vmx.s
grep -n -H ".globl" ./vmm/memory/ept/invept.s
grep -n -H ".globl" ./vmm/utils/utils_asm.s
grep -n -H ".globl" ./vmm/vmexit/teardown_thunk.s
