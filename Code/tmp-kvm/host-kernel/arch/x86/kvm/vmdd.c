#include <asm/page.h>
#include <linux/kvm_host.h>
#include <asm/kvm_host.h>
#include <asm/vmdd.h>
#include <linux/types.h>
#include <linux/tcioDD.h>
#include "x86.h"

extern int tciodd_serviceInitialized;

// the tciodd device
extern struct tciodd_dev *tciodd_device;

// the request queue and its semaphore
extern struct semaphore    tciodd_reqserviceqsem; 
extern struct tciodd_Qent* tciodd_reqserviceq;

// the response queue and its semaphore
extern struct semaphore    tciodd_resserviceqsem; 
extern struct tciodd_Qent* tciodd_resserviceq;

int vmdd_read(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count) {
    struct tciodd_dev*  dev= tciodd_device;
    ssize_t             retval= 0;
    // TODO(tmroeder): find a better id, since this might not be unique across virtual machines
    int                 pid= vcpu->vcpu_id;
    struct tciodd_Qent* pent= NULL;

    if (!tciodd_serviceInitialized) {
      return -EFAULT;
    }

    printk(KERN_DEBUG "vmdd_read: read %d, privdata: %08lx, pid: %d\n", 
            (int)count, (long int)dev, pid);

    // if something is on the response queue, fill buffer, otherwise return
    if (down_interruptible(&tciodd_resserviceqsem) == 0) {
      printk(KERN_DEBUG "tcioDD: read looking on response queue for %d\n",
	     pid);
      pent = tciodd_findQentbypid(tciodd_resserviceq, pid);
      up(&tciodd_resserviceqsem);
    }

    if (pent == NULL) {
      // we read 0 bytes
      return 0;
    }

    printk(KERN_DEBUG "vmdd_read: copying buffer for vcpu %d\n", pid);
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    if (pent->m_sizedata <= count) {
      // try to write to the guest and propagate the page fault if
      // there is one while reading
      struct x86_exception e;
      if (kvm_write_guest_virt_system(&vcpu->arch.emulate_ctxt, buf,
				      pent->m_data, pent->m_sizedata, &e)) {
	kvm_inject_page_fault(vcpu, &e);
	return -EFAULT;
      }

      retval = pent->m_sizedata;
    } else {
      retval= -EFAULT;
    }

    if (down_interruptible(&tciodd_resserviceqsem) == 0) {
        tciodd_removeQent(&tciodd_resserviceq, pent);
    
        // erase and free entry and data
        if(pent->m_data!=NULL) {
            memset(pent->m_data, 0, pent->m_sizedata);
            kfree(pent->m_data);
        }
        pent->m_data= NULL;
        tciodd_deleteQent(pent);
        up(&tciodd_resserviceqsem);
    }

    up(&dev->sem);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: read complete for %d\n", pid);
#endif
    return retval;
}

int vmdd_write(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count) {
    struct tciodd_dev*      dev= tciodd_device;
    ssize_t                 retval= -ENOMEM;
    byte*                   databuf= NULL;
    struct tciodd_Qent*     pent= NULL;
    tcBuffer*               pCBuf= NULL;
    // TODO(tmroeder): find out if this is the right representation
    // for the VM/VCPU combination
    int                     pid= vcpu->vcpu_id;
    struct x86_exception    e;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: write %d for %d\n", (int)count, pid);
#endif
    if (down_interruptible(&dev->sem)) {
        return -ERESTARTSYS;
    }

    if (!tciodd_serviceInitialized) {
      retval = -EFAULT;
      goto out;
    }

    // add to tciodd_reqserviceQ then process
    if (count < sizeof(tcBuffer)) {
        retval= -EFAULT;
        goto out;
    }

    databuf = (byte*) kmalloc(count, GFP_KERNEL);
    if(databuf==NULL) {
        retval= -EFAULT;
        goto out;
    }

    // read the memory from the guest and propagate the fault if there is one
    if (kvm_read_guest_virt(&vcpu->arch.emulate_ctxt, buf, databuf,
				   count, &e)) {
      kvm_inject_page_fault(vcpu, &e);
      return -EFAULT;
    }

    // make tcheader authoritative
    pCBuf= (tcBuffer*) databuf;
    pCBuf->m_procid= pid;

    // the pid here can never be the service pid, since it's coming
    // from a different source
    // TODO(tmroeder): force the process space and the vmpid space to be
    // disjoint (maybe make all vcpu pids negative?)
    pCBuf->m_origprocid= pid;

    pent= tciodd_makeQent(pid, count, databuf, NULL);
    if (pent == NULL) {
        retval= -EFAULT;
        goto out;
    }

    if (down_interruptible(&tciodd_reqserviceqsem)) {
        retval= -ERESTARTSYS;
        goto out;
    }

    printk(KERN_DEBUG "tcioDD: write, appending entry\n");
    tciodd_appendQent(&tciodd_reqserviceq, pent);
    up(&tciodd_reqserviceqsem);
    retval= count;

out:
    up(&dev->sem);
    
    // TODO(tmroeder): is this going to take too much time for a
    // hypercall handler to use?
    while(tciodd_processService());

    return retval;
}
