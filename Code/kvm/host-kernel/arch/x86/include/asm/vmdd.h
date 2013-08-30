#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/const.h>
#include <asm/kvm_para.h>
#include <linux/kvm_types.h>

#define TESTDEVICE
#define VMDD

#define KVM_HYPERCALL_READ_FROM_TCSERVICE	13577
#define KVM_HYPERCALL_WRITE_TO_TCSERVICE	13576

#define tc_hypercall0(type, name)			\
({							\
	long __res;					\
	__res = kvm_hypercall0(name);	\
	(type)__res;					\
})
#define tc_hypercall1(type, name, a1)			\
({							\
	long __res;					\
	__res = kvm_hypercall1(name, (unsigned long)a1);	\
	(type)__res;					\
})
#define tc_hypercall2(type, name, a1, a2)		\
({							\
	long __res;					\
	__res = kvm_hypercall2(name, (unsigned long)a1,	\
	(unsigned long)a2);				\
	(type)__res;					\
})
#define tc_hypercall3(name, a1, a2, a3)		\
({							\
	long __res;					\
	__res = kvm_hypercall3(name, (unsigned long)a1,	\
	(unsigned long)a2,				\
	(unsigned long)a3);				\
	(type)__res;					\
})
#define tc_hypercall4(type, name, a1, a2, a3, a4)		\
({							\
	long res;					\
	res = kvm_hypercall4(name, (unsigned long)a1,	\
	(unsigned long)a2,				\
	(unsigned long)a3,				\
	(unsigned long)a4);				\
	(type)res;					\
})

int vmdd_read(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count);
int vmdd_write(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count);
