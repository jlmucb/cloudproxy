/*
 * File ktcioDD.c - 
 *	Virtualized trusted service device driver. 
 *	This is heavily based on the tcioDD.c driver code.
 *
 * This file and derived words are subject to the terms and conditions
 * set forth in the file LICENSE in this directory.
 */  

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include "ktcioDD.h"
#include <asm/vmdd.h>

#define LINUXLICENSED

int ktciodd_major = KTCIODD_MAJOR;
int ktciodd_minor = 0;
int ktciodd_nr_devs = KTCIODD_NR_DEVS;

//
//  For udev and dynamic allocation of device
static struct class*    pclass= NULL;
static struct device*   pdevice= NULL;

module_param(ktciodd_major, int, S_IRUGO);
module_param(ktciodd_minor, int, S_IRUGO);
module_param(ktciodd_nr_devs, int, S_IRUGO);

struct ktciodd_dev*  ktciodd_devices;

struct file_operations ktciodd_fops= {
    .owner=    THIS_MODULE,
    .read=     ktciodd_read,
    .write=    ktciodd_write,
    .open=     ktciodd_open,
    .release=  ktciodd_close,
};

static struct class*    kclass= NULL;
static struct device*   kdevice= NULL;

// Set up the char_dev structure for this device.
void ktciodd_setup_cdev(struct ktciodd_dev *dev, int index)
{
    int err, devno;
   
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: setup cdev started\n");
#endif
    devno= MKDEV(ktciodd_major, ktciodd_minor+index);
    cdev_init(&dev->kdev, &ktciodd_fops);
    dev->kdev.owner= THIS_MODULE;
    dev->kdev.ops= &ktciodd_fops;
    err= cdev_add (&dev->kdev, devno, 1);
    if(err)
        printk(KERN_NOTICE "Error %d adding ktciodd %d", err, index);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktcioDD: setup cdev complete, devno is %08x\n", devno);
#endif

}

int ktciodd_close(struct inode *inode, struct file *filp) {
    int         i;
    dev_t       devno= MKDEV(ktciodd_major, ktciodd_minor);

#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktcioDD: close started\n");
#endif
    // Get rid of dev entries
    if(ktciodd_devices) {
        for(i= 0; i<ktciodd_nr_devs; i++) {
            cdev_del(&ktciodd_devices[i].kdev);
        }
        kfree(ktciodd_devices);
    }

    if(kclass!=NULL && kdevice!=NULL) {
        device_destroy(kclass, MKDEV(ktciodd_major,0));
        kdevice= NULL;
    }
    if(kclass!=NULL) {
        class_destroy(kclass);
        kclass= NULL;
    }

    // cleanup_module isn't called if registering failed
    unregister_chrdev_region(devno, ktciodd_nr_devs);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktcioDD: close complete\n");
#endif

    return 1;
}

void ktciodd_cleanup(void)
{
    int         i;
    dev_t       devno= MKDEV(ktciodd_major, ktciodd_minor);

#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktciodd: cleanup started\n");
#endif
    // Get rid of dev entries
    if(ktciodd_devices) {
        for(i= 0; i<ktciodd_nr_devs; i++) {
            cdev_del(&ktciodd_devices[i].kdev);
        }
        kfree(ktciodd_devices);
    }

    if(pclass!=NULL && pdevice!=NULL) {
        device_destroy(pclass, MKDEV(ktciodd_major,0));
        pdevice= NULL;
    }
    if(pclass!=NULL) {
        class_destroy(pclass);
        pclass= NULL;
    }

    // cleanup_module isn't called if registering failed
    unregister_chrdev_region(devno, ktciodd_nr_devs);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktciodd: cleanup complete\n");
#endif
}

int ktciodd_init(void)
{
    int     result, i;
    dev_t   dev= 0;

    if(ktciodd_major) {
        // static registration
        dev= MKDEV(ktciodd_major, ktciodd_minor);
        result= register_chrdev_region(dev, ktciodd_nr_devs, "ktciodd");
    } 
    else {
        // dynamic registration
        result= alloc_chrdev_region(&dev, ktciodd_minor, ktciodd_nr_devs, "ktciodd");
        ktciodd_major= MAJOR(dev);
    }
    if(result<0) {
        printk(KERN_WARNING "ktciodd: can't get major %d\n", ktciodd_major);
        return result;
    }

    pclass= class_create(THIS_MODULE, "ktciodd");
    if(pclass==NULL)
        goto fail;
    pdevice= device_create(pclass, NULL, MKDEV(ktciodd_major,0), NULL, "ktciodd0");
    if(pdevice==NULL)
        goto fail;

    ktciodd_devices= kmalloc(ktciodd_nr_devs*sizeof(struct ktciodd_dev), GFP_KERNEL);
    if(!ktciodd_devices) {
        result= -ENOMEM;
        goto fail;
    }
    memset(ktciodd_devices, 0, ktciodd_nr_devs*sizeof(struct ktciodd_dev));

    // Initialize each device. 
    for(i= 0; i<ktciodd_nr_devs; i++) {
        ktciodd_setup_cdev(&ktciodd_devices[i], i);
    }
#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktciodd: ktciodd_init complete\n");
#endif
    return 0;

fail:
    ktciodd_cleanup();
    return result;
}


int ktciodd_open(struct inode *inode, struct file *filp) {
    int     result, i;
    dev_t   dev= 0;

    if(ktciodd_major) {
        // static registration
        dev= MKDEV(ktciodd_major, ktciodd_minor);
        result= register_chrdev_region(dev, ktciodd_nr_devs, "ktciodd");
    } 
    else {
        // dynamic registration
        result= alloc_chrdev_region(&dev, ktciodd_minor, ktciodd_nr_devs, "ktciodd");
        ktciodd_major= MAJOR(dev);
    }
    if(result<0) {
        printk(KERN_WARNING "ktciodd: can't get major %d\n", ktciodd_major);
        return result;
    }

    kclass= class_create(THIS_MODULE, "ktcioDD");
    if(kclass==NULL)
        goto fail;
    kdevice= device_create(kclass, NULL, MKDEV(ktciodd_major,0), NULL, "ktcioDD0");
    if(kdevice==NULL)
        goto fail;

    ktciodd_devices= kmalloc(ktciodd_nr_devs*sizeof(struct ktciodd_dev), GFP_KERNEL);
    if(!ktciodd_devices) {
        result= -ENOMEM;
        goto fail;
    }
    memset(ktciodd_devices, 0, ktciodd_nr_devs*sizeof(struct ktciodd_dev));

    // Initialize each device. 
    for(i= 0; i<ktciodd_nr_devs; i++) {
        ktciodd_setup_cdev(&ktciodd_devices[i], i);
    }
#ifdef TESTDEVICE
    printk(KERN_DEBUG "ktcioDD: ktciodd_init complete\n");
#endif
    return 0;

fail:
    ktciodd_close(inode, filp);
    return result;
}

ssize_t ktciodd_read(struct file *filp, char __user *buf, size_t count,
                    loff_t *f_pos) {

  /* Pass the buffer pointer down to the host kernel to see if there is anything to read.
   * Poll the hypercall interface here until it reads something, then copy it out and return.
   * TODO(tmroeder): the right way to do this is to wait for an interrupt from the host kernel
   * that signals the availability of data for the reply to this read.
   */
  ssize_t result = 0;
  
  void* databuf= kmalloc(count, GFP_KERNEL);

  while((result = (ssize_t)kvm_hypercall2(KVM_HYPERCALL_READ_FROM_TCSERVICE,
					  (unsigned long)databuf,
					  (unsigned long)count)) == 0) {
    yield();
  }

  // copy the received buffer back up to the user
  if (copy_to_user(buf, databuf, result))
    result = -EFAULT;

  kfree(databuf);
  return result;
}

ssize_t ktciodd_write(struct file *filp, const char __user *buf, size_t count,
                     loff_t *f_pos) {

  ssize_t ret = 0;

  void *databuf = kmalloc(count, GFP_KERNEL);
  if (databuf == NULL)
    return -ENOMEM;

  if (copy_from_user(databuf, buf, count)) {
    ret = -EFAULT;
    goto out;
  }

  // pass this data down to the the host kernel by a hypercall
  ret = (ssize_t)kvm_hypercall2(KVM_HYPERCALL_WRITE_TO_TCSERVICE,
				(unsigned long)databuf,
				(unsigned long)count);
 out:
  kfree(databuf);
  return ret;
}

#ifdef LINUXLICENSED
MODULE_LICENSE("GPL");
module_init(ktciodd_init);
module_exit(ktciodd_cleanup);
#endif
