#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/const.h>
#include <asm/kvm_para.h>
#include <linux/kvm_types.h>
#include <asm/kvm_host.h>

#define TESTDEVICE
#define VMDD

#define KVM_HYPERCALL_READ_FROM_TCSERVICE	13577
#define KVM_HYPERCALL_WRITE_TO_TCSERVICE	13576

int vmdd_read(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count);
int vmdd_write(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count);
