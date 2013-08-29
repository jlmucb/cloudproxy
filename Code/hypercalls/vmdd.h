#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/const.h>
#include <asm/kvm_para.h>

#define TESTDEVICE
#define VMDD

#define KVM_HYPERCALL_CONNECT_TO_TCSERVICE	13579
#define KVM_HYPERCALL_DISCONNECT_FROM_TCSERVICE	13578
#define KVM_HYPERCALL_READ_FROM_TCSERVICE	13577
#define KVM_HYPERCALL_WRITE_TO_TCSERVICE	13576
#define KVM_HYPERCALL_IOCTL_TO_TCSERVICE	13575

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


/*
struct kvm;
struct tciodd_dev; 
struct file_operations;

int vmdd_open(struct inode *inode, struct file *fp);
int vmdd_close(struct inode *inode, struct file *fp);
ssize_t vmdd_read(struct file *fp, const char __user *buf, size_t count, loff_t *pos);
ssize_t vmdd_write(struct file *fp, const char __user *buf, size_t count, loff_t *pos);

struct file_operations vmdd_ops = {
	.owner = THIS_MODULE,
	.read = vmdd_read,
	.write = vmdd_write,
	.open = vmdd_open,
	.release = vmdd_close,
};

struct vmdd_cb {
	struct kvm *kvm;
	struct tciodd_dev *tcdev;
	int tcdevfd;
};

*/
