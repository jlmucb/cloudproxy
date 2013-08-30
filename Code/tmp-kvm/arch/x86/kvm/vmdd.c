#include <asm/page.h>
#include <linux/kvm_host.h>
#include <asm/vmdd.h>
#include <linux/types.h>
#include <linux/tcioDD.h>

//check if the tcService is running.  If yes, connect to it; else start the service and then connect.

extern int tciodd_serviceInitialized;
extern int tciodd_servicepid;

//kernel externs

int vmdd_connect(struct kvm_vcpu *vcpu) {

	int ret = 0, vmpid;
	if (!tciodd_serviceInitialized) {
		ret = tciodd_init();
		if (ret != 0) {
    			printk(KERN_DEBUG "tcioDD: tciodd_init complete\n");
			tciodd_serviceInitialized = 1;
		} //endif ret
	} //endif tciodd_serviceInitialize 
	
	/*
 	 * REK: The vmpid is the pid of the VM that requested this service.  This pid
	 *	should be used for authentication/verfication
	 */
	vmpid = vcpu->vcpu_id;
	//REK: I believe this field is used to identify a process for all the operations,
	// but please double check.
	tciodd_servicepid = vmpid;

	return ret;
}//end vmdd_connect

int vmdd_disconnect(struct kvm_vcpu *vcpu) {
	int ret = 0;

	//REK: I don't think we need this hypercall
	return ret;
}//end vmdd_disconnect

int vmdd_read(struct kvm_vcpu *vcpu, struct file *fp, char *buf, ssize_t count, loff_t *pos) {

	int ret = 0;
		ret = tciodd_read(fp, buf, count, pos);
	return ret;
}//end vmdd_read

int vmdd_write(struct kvm_vcpu *vcpu, struct file *fp, char *buf, ssize_t count, loff_t *pos) {
	int ret = 0;
		ret = tciodd_write(fp, buf, count, pos);
	return ret;
}//vmdd_write
