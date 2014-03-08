
void save_cpu_state(VMM_GUEST_CPU_STARTUP_STATE *s)
{
    IA32_GDTR gdtr;
    IA32_IDTR idtr;
    IA32_SELECTOR sel;
    IA32_SEGMENT_DESCRIPTOR *desc;

    s->size_of_this_struct = sizeof(VMM_GUEST_CPU_STARTUP_STATE);
    s->version_of_this_struct = VMM_GUEST_CPU_STARTUP_STATE_VERSION;

    __readgdtr(&gdtr);
    __sidt(&idtr);
    s->control.gdtr.base = (UINT64)gdtr.base;
    s->control.gdtr.limit = (UINT32)gdtr.limit;
    s->control.idtr.base = (UINT64)idtr.base;
    s->control.idtr.limit = (UINT32)idtr.limit;
    s->control.cr[IA32_CTRL_CR0] = __readcr0();
    s->control.cr[IA32_CTRL_CR2] = __readcr2();
    s->control.cr[IA32_CTRL_CR3] = __readcr3();
    s->control.cr[IA32_CTRL_CR4] = __readcr4();

    s->msr.msr_sysenter_cs = (UINT32)__readmsr(IA32_MSR_SYSENTER_CS);
    s->msr.msr_sysenter_eip = __readmsr(IA32_MSR_SYSENTER_EIP);
    s->msr.msr_sysenter_esp = __readmsr(IA32_MSR_SYSENTER_ESP);
    s->msr.msr_efer = __readmsr(IA32_MSR_EFER);
    s->msr.msr_pat = __readmsr(IA32_MSR_PAT);
    s->msr.msr_debugctl = __readmsr(IA32_MSR_DEBUGCTL);
    s->msr.pending_exceptions = 0;
    s->msr.interruptibility_state = 0;
    s->msr.activity_state = 0;
    s->msr.smbase = 0;

    sel.sel16 = __readldtr();

    if (sel.bits.index != 0)
        return;

    s->seg.segment[IA32_SEG_LDTR].attributes = 0x00010000;
    s->seg.segment[IA32_SEG_TR].attributes = 0x0000808b;
    s->seg.segment[IA32_SEG_TR].limit = 0xffffffff;
    save_segment_data(__readcs(), &s->seg.segment[IA32_SEG_CS]);
    save_segment_data(__readds(), &s->seg.segment[IA32_SEG_DS]);
    save_segment_data(__reades(), &s->seg.segment[IA32_SEG_ES]);
    save_segment_data(__readfs(), &s->seg.segment[IA32_SEG_FS]);
    save_segment_data(__readgs(), &s->seg.segment[IA32_SEG_GS]);
    save_segment_data(__readss(), &s->seg.segment[IA32_SEG_SS]);
    return;
}

