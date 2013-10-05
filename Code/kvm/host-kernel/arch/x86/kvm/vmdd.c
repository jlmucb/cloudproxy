#include <asm/page.h>
#include <linux/kvm_host.h>
#include <asm/kvm_host.h>
#include <asm/vmdd.h>
#include <linux/types.h>
#include <linux/kvmtciodd.h>
#include "x86.h"

extern int kvmtciodd_serviceInitialized;

// the kvmtciodd device
extern struct kvmtciodd_dev*    kvmtciodd_device;

// the request queue and its semaphore
extern struct semaphore         kvmtciodd_reqserviceqsem; 
extern struct kvmtciodd_Qent*   kvmtciodd_reqserviceq;

// the response queue and its semaphore
extern struct semaphore         kvmtciodd_resserviceqsem; 
extern struct kvmtciodd_Qent*   kvmtciodd_resserviceq;

int vmdd_read(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count) {
    struct kvmtciodd_dev*   dev= kvmtciodd_device;
    ssize_t                 retval= 0;
#if 0
    // TODO(tmroeder): find a better id
    int                     pid= vcpu->vcpu_id;
#else
    int                     pid= pid_nr(vcpu->pid);
#endif
    struct kvmtciodd_Qent*  pent= NULL;
    printk("vmdd: in vmdd_read with pid %d, vcpuid: %d\n", pid, vcpu->pid);

    if (!kvmtciodd_serviceInitialized) {
      printk("vmdd: kvmtciodd not initialized\n");
      return -EFAULT;
    }

    printk("vmdd_read: read %d, privdata: %08lx, pid: %d\n", 
            (int)count, (long int)dev, pid);

    // if something is on the response queue, fill buffer, otherwise return
    if (down_interruptible(&kvmtciodd_resserviceqsem) == 0) {
      printk("kvmkvmtciodd: read looking on response queue for %d\n",
             pid);
      pent = kvmtciodd_findQentbypid(kvmtciodd_resserviceq, pid);
      up(&kvmtciodd_resserviceqsem);
    }

    if (pent == NULL) {
      // we read 0 bytes
      return 0;
    }

    printk("vmdd_read: copying buffer for vcpu %d\n", pid);
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    if (pent->m_sizedata <= count) {
      // try to write to the guest and propagate the page fault if
      // there is one while reading
      struct x86_exception e;
      printk("vmdd_read: trying to write to the guest\n");
      if (kvm_write_guest_virt_system(&vcpu->arch.emulate_ctxt, buf,
                                      pent->m_data, pent->m_sizedata, &e)) {
        kvm_inject_page_fault(vcpu, &e);
        printk("vmdd_read: couldn't read; injected page fault\n");
        return -EFAULT;
      }

      printk("vmdd_read: read %d bytes\n", pent->m_sizedata);

      retval = pent->m_sizedata;
    } else {
      printk("vmdd_read: not enough space: need %d and have %ld\n", pent->m_sizedata, count);
      retval= -EFAULT;
    }

    if (down_interruptible(&kvmtciodd_resserviceqsem) == 0) {
        kvmtciodd_removeQent(&kvmtciodd_resserviceq, pent);
        printk("vmdd_read: deleting read request from the queue\n");
        // erase and free entry and data
        if(pent->m_data!=NULL) {
            memset(pent->m_data, 0, pent->m_sizedata);
            kfree(pent->m_data);
        }
        pent->m_data= NULL;
        kvmtciodd_deleteQent(pent);
        up(&kvmtciodd_resserviceqsem);
    }

    up(&dev->sem);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmkvmtciodd: read complete for %d\n", pid);
#endif
    return retval;
}

int vmdd_write(struct kvm_vcpu *vcpu, gva_t buf, ssize_t count) {
    struct kvmtciodd_dev*   dev= kvmtciodd_device;
    ssize_t                 retval= -ENOMEM;
    byte*                   databuf= NULL;
    struct kvmtciodd_Qent*  pent= NULL;
    tcBuffer*               pCBuf= NULL;
    // TODO: is this the right pid?
#if 0
    int                     pid= vcpu->vcpu_id;
#else
    int                     pid= pid_nr(vcpu->pid);
#endif
    struct x86_exception    e;

    printk("kvmkvmtciodd: write %d for %d\n", (int)count, pid);
    if (down_interruptible(&dev->sem)) {
        return -ERESTARTSYS;
    }

    if (!kvmtciodd_serviceInitialized) {
      printk("vmdd_write: the kvmtciodd service is not initialized\n");
      retval = -EFAULT;
      goto out;
    }

    // add to kvmtciodd_reqserviceQ then process
    if (count < sizeof(tcBuffer)) {
      printk("vmdd_write: not enough space: %ld vs %lu\n", count, sizeof(tcBuffer));
        retval= -EFAULT;
        goto out;
    }

    databuf = (byte*) kmalloc(count, GFP_KERNEL);
    if(databuf==NULL) {
        retval= -EFAULT;
        goto out;
    }

    printk("vmdd_write: Trying to read from guest memory\n");
    // read the memory from the guest and propagate the fault if there is one
    if (kvm_read_guest_virt(&vcpu->arch.emulate_ctxt, buf, databuf,
                                   count, &e)) {
      kvm_inject_page_fault(vcpu, &e);
      printk("vmdd_write: failed to read from guest memory; injected page fault\n");
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

    pent= kvmtciodd_makeQent(pid, count, databuf, NULL);
    if (pent == NULL) {
        retval= -EFAULT;
        goto out;
    }

    if (down_interruptible(&kvmtciodd_reqserviceqsem)) {
        retval= -ERESTARTSYS;
        goto out;
    }

    printk("vmdd_write: write, appending entry\n");
    kvmtciodd_appendQent(&kvmtciodd_reqserviceq, pent);
    up(&kvmtciodd_reqserviceqsem);
    retval= count;

out:
    up(&dev->sem);
    
    printk("vmdd_write: processing requests in kvmtciodd\n");
    // TODO(tmroeder): is this going to take too much time for a
    // hypercall handler to use?
    while(kvmtciodd_processService());
    printk("vmdd_write: done processing requests in kvmtciodd\n");

    return retval;
}
