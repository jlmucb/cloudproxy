//
//  File: kvmtciodd.c
//      Trusted service device driver
//
//  This file and derived words are subject to the terms and conditions
//  set forth in the file LICENSE in this directory.


#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/device.h>

#include "algs.h"
#include <linux/kvmtciodd.h>
#include "tcServiceCodes.h"

#include "serviceHash.inc"
#include "policyKey.inc"

// remove this define if NOT compiled for Linux
#define LINUXLICENSED


/*
 * Some code from this file was derived from material developed by
 *     Alessandro Rubini and Jonathan Corbet and subject to the
 *     following terms.
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 */

#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/kvmtciodd.h>
/* #include <asm/system.h> */
#include <asm/uaccess.h>


#define TESTDEVICE
#define TIMEOUT 8000

#ifndef SHA256HASHSIZE
#define SHA256HASHSIZE 32
#endif


// ----------------------------------------------------------------------------


unsigned    kvmtciodd_serviceInitialized= 0;
int         kvmtciodd_servicepid= 0;


int         kvmtciodd_major=   KVMTCIODD_MAJOR;
int         kvmtciodd_minor=   0;

// there can only be such device
int         kvmtciodd_nr_devs= 1;

// there will never be more than one, since there is only one
// tcService at a time that connects, and all other calls come down
// through KVM rather than from a process that opens /dev/kvmtciodd{N}
struct kvmtciodd_dev *kvmtciodd_device = NULL;


module_param(kvmtciodd_major, int, S_IRUGO);
module_param(kvmtciodd_minor, int, S_IRUGO);
module_param(kvmtciodd_nr_devs, int, S_IRUGO);

struct file_operations kvmtciodd_fops= {
    .owner=    THIS_MODULE,
    .read=     kvmtciodd_read,
    .write=    kvmtciodd_write,
    .open=     kvmtciodd_open,
    .release=  kvmtciodd_close,
};


//  Read and write buffers have the following format:
//      tcBuffer header || data

struct semaphore    kvmtciodd_reqserviceqsem; 
struct kvmtciodd_Qent* kvmtciodd_reqserviceq= NULL;
struct semaphore    kvmtciodd_resserviceqsem; 
struct kvmtciodd_Qent* kvmtciodd_resserviceq= NULL;


//
//  For udev and dynamic allocation of device
static struct class*    pclass= NULL;
static struct device*   pdevice= NULL;



// ----------------------------------------------------------------------------


#ifdef TESTDEVICE


// These are unsafe but they are only used for debug

void kvmtcio_printcmdbuffer(byte* pB)
{
    tcBuffer* pC= (tcBuffer*) pB;
    pB+= sizeof(tcBuffer);
    printk(KERN_DEBUG "procid: %d, origprocid: %d, req: %d, size: %d\n",
           pC->m_procid, pC->m_origprocid, pC->m_reqID, pC->m_reqSize);
}


void kvmtcio_printent(struct kvmtciodd_Qent* pE)
{
    int     n;

    n= pE->m_sizedata;
    printk(KERN_DEBUG "pid: %d, size: %d.  ", pE->m_pid, n);
#if 0
    byte* pB= pE->m_data;
    if(n>20)
        n= 20;
    for(int i=0; i<n; i++) {
        printk(KERN_DEBUG "%02x::", *pB);
        pB++;
    }
#endif
    printk(KERN_DEBUG "\n");
}


void kvmtcio_printlist(struct kvmtciodd_Qent* pE)
{
    int     n= 0;

    while(pE!=NULL) {
        kvmtcio_printent(pE);
        pE= (struct kvmtciodd_Qent*) pE->m_next;
        n++;
    }
    printk(KERN_DEBUG "  %d list elements\n", n);
}


void kvmtcio_printrequestQ(void)
{
    printk(KERN_DEBUG "kvmtciodd: request list\n");
    kvmtcio_printlist(kvmtciodd_reqserviceq);
}


void kvmtcio_printresponseQ(void)
{
    printk(KERN_DEBUG "kvmtciodd: response list\n");
    kvmtcio_printlist(kvmtciodd_resserviceq);
}


#endif


// ------------------------------------------------------------------------------


struct kvmtciodd_Qent* kvmtciodd_makeQent(int pid, int sizedata, byte* data, 
                                    struct kvmtciodd_Qent* next)
{
    struct kvmtciodd_Qent* pent= NULL;
    void*               area= kmalloc(sizeof(struct kvmtciodd_Qent), GFP_KERNEL);

    if(area==NULL)
        return NULL;
    pent= (struct kvmtciodd_Qent*)area;
    pent->m_pid= current->pid;
    pent->m_data= data;
    pent->m_sizedata= sizedata;
    pent->m_next= NULL;
    return pent;
}


void kvmtciodd_deleteQent(struct kvmtciodd_Qent* pent)
{
    memset((void*)pent, 0, sizeof(struct kvmtciodd_Qent));
    kfree((void*)pent);
    return;
}


int  kvmtciodd_insertQent(struct kvmtciodd_Qent** phead, struct kvmtciodd_Qent* pent)
{
    pent->m_next= *phead;
    *phead= pent;
    return 1;
}


int  kvmtciodd_appendQent(struct kvmtciodd_Qent** phead, struct kvmtciodd_Qent* pent)
{
    struct kvmtciodd_Qent* p;

    pent->m_next= NULL;
    if(*phead==NULL) {
        *phead= pent;
        return 1;
    }
    p= *phead;

    while(p->m_next!=NULL) {
        p= p->m_next;
    }
    p->m_next= pent;
    return 1;
}


int  kvmtciodd_removeQent(struct kvmtciodd_Qent** phead, struct kvmtciodd_Qent* pent)
{
    struct kvmtciodd_Qent* pPrev= NULL;
    struct kvmtciodd_Qent* p= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: removeQent\n");
#endif
    if(*phead==NULL)
        return 0;
    if(pent==*phead) {
        *phead= pent->m_next;
        return 1;
    }
    pPrev= *phead;
    p= (*phead)->m_next;

    while(p!=NULL) {
        if(p==pent) {
            pPrev->m_next= p->m_next;
            return 1;
        }
        pPrev= p;
        p= p->m_next;
    }
    return 0;
}

void kvmtciodd_clearQent(struct kvmtciodd_Qent** phead)
{
  struct kvmtciodd_Qent* cur = NULL;
  if (phead == NULL) return;

  cur = *phead;
  while (cur != NULL) {
    // remove the current head
    *phead = cur->m_next;

    kvmtciodd_deleteQent(cur);
    cur = *phead;
  }
}

struct kvmtciodd_Qent* kvmtciodd_findQentbypid(struct kvmtciodd_Qent* head, int pid)
{
    struct kvmtciodd_Qent* p= head;

    while(p!=NULL) {
        if(p->m_pid==pid)
            return p;
        p= p->m_next;
    }
    return NULL;
}


// --------------------------------------------------------------------


bool kvmtcio_sendTerminate(int procid, int origprocid)
{
    tcBuffer*           newhdr= NULL;
    int                 newdatasize;
    byte*               newdata;
    struct kvmtciodd_Qent* pent= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: sendTerminate(%d, %d)\n", procid, origprocid);
#endif
    //  create new buffer
    newdatasize= sizeof(tcBuffer);
    newdata= kmalloc(newdatasize, GFP_KERNEL);
    if(newdata==NULL)
        return false;

    //  make header and copy answer
    newhdr= (tcBuffer*) newdata;
    newhdr->m_procid= origprocid;
    newhdr->m_reqID= TCSERVICETERMINATE;
    newhdr->m_ustatus= TCIOSUCCESS;
    newhdr->m_origprocid= origprocid;
    newhdr->m_reqSize= 0;

    //  adjust pent
    pent= kvmtciodd_makeQent(kvmtciodd_servicepid, newdatasize, newdata, NULL);
    if(pent==NULL)
        return false;

    if(down_interruptible(&kvmtciodd_reqserviceqsem)) 
        return false;
    kvmtciodd_appendQent(&kvmtciodd_reqserviceq, pent);
    up(&kvmtciodd_reqserviceqsem);
    return true;
}

bool kvmtcio_copyResultandqueue(struct kvmtciodd_Qent* pent, u32 type, int sizebuf, byte* buf)
//  Copy from buf to new ent
{
    int         n= 0;
    tcBuffer*   hdr= (tcBuffer*)pent->m_data;
    tcBuffer*   newhdr= NULL;
    int         newdatasize;
    byte*       newdata;
    int         m= 0;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: copyResultandqueue\n");
#endif
    //  create new buffer
    newdatasize= sizebuf+sizeof(u32)+sizeof(int)+sizeof(tcBuffer);
    newdata= kmalloc(newdatasize, GFP_KERNEL);
    if(newdata==NULL)
        return false;

    //  make header and copy answer
    newhdr= (tcBuffer*) newdata;
    newhdr->m_procid= hdr->m_procid;
    newhdr->m_reqID= hdr->m_reqID;
    newhdr->m_ustatus= TCIOFAILED;
    newhdr->m_origprocid= hdr->m_origprocid;
    newhdr->m_reqSize= newdatasize-sizeof(tcBuffer);
    m= sizeof(tcBuffer);
    memcpy(newdata+m, (byte*) &type, sizeof(u32));
    m+= sizeof(u32);
    memcpy(newdata+m, (byte*) &sizebuf, sizeof(int));
    m+= sizeof(int);
    memcpy(newdata+m, buf, sizebuf);

    //  delete old buffer if non NULL
    if(pent->m_data!=NULL) {
        kfree(pent->m_data);
        pent->m_data= NULL;
    }

    //  adjust pent
    hdr= (tcBuffer*)newdata;
    pent->m_sizedata= newdatasize;
    pent->m_data= newdata;
    newhdr->m_ustatus= TCIOSUCCESS;

    if(down_interruptible(&kvmtciodd_resserviceqsem)) 
        return false;
    n= kvmtciodd_appendQent(&kvmtciodd_resserviceq, pent);
    up(&kvmtciodd_resserviceqsem);
    return true;
}


bool kvmtcio_queueforService(struct kvmtciodd_Qent* pent, u32 appReq, u32 serviceReq)
{
    int         n;
    tcBuffer*   hdr= (tcBuffer*)pent->m_data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: queueforService appCode: %d serviceCode: %d\n",
            appReq, serviceReq);
#endif
    // adjust and append to waitq
    if(down_interruptible(&kvmtciodd_resserviceqsem)) 
        return false;
    hdr->m_origprocid= hdr->m_procid;
    hdr->m_procid= kvmtciodd_servicepid;
    hdr->m_reqID= serviceReq;
    hdr->m_ustatus= TCIOSUCCESS;
    pent->m_pid= kvmtciodd_servicepid;
    n= kvmtciodd_appendQent(&kvmtciodd_resserviceq, pent);
    up(&kvmtciodd_resserviceqsem);
    return true;
}


bool kvmtcio_queueforApp(struct kvmtciodd_Qent* pent, u32 appReq, u32 serviceReq)
{
    tcBuffer*   hdr= (tcBuffer*) pent->m_data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: queueforApp appCode: %d serviceCode: %d\n",
            appReq, serviceReq);
#endif
    // adjust and append to waitq
    if(down_interruptible(&kvmtciodd_resserviceqsem))
        return false;
    hdr->m_procid= hdr->m_origprocid;
    hdr->m_reqID= appReq;
    pent->m_pid= hdr->m_origprocid;
    kvmtciodd_appendQent(&kvmtciodd_resserviceq, pent);
    up(&kvmtciodd_resserviceqsem);
    return true;
}


bool kvmtciodd_processService(void)
//  Take entry off request queue, service it and put it on response queue
{
    int                 n= 0;
    struct kvmtciodd_Qent* pent= NULL;
    tcBuffer*           hdr= NULL;
    int                 datasize= 0;
    byte*               data= NULL;
    bool                fRet= true;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: processService started\n");
    kvmtcio_printrequestQ(); kvmtcio_printresponseQ();
#endif
    if(down_interruptible(&kvmtciodd_reqserviceqsem)) 
        return false;
    pent= kvmtciodd_reqserviceq;
    n= kvmtciodd_removeQent(&kvmtciodd_reqserviceq, pent);
    up(&kvmtciodd_reqserviceqsem);

    if(n<=0 || pent==NULL)
        return false;

    datasize= pent->m_sizedata;
    data= pent->m_data;
    hdr= (tcBuffer*)data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: processService got ent from reqQ %d, size: %d\n", 
           pent->m_pid, pent->m_sizedata);
    kvmtcio_printcmdbuffer(pent->m_data);
#endif

    // don't forget to wake up reading processes
    switch(hdr->m_reqID) {

      // For first four, no need to go to service
      case TCSERVICEGETPOLICYKEYFROMAPP:
        if(!kvmtcio_copyResultandqueue(pent, kvmtciodd_policykeyType, kvmtciodd_sizepolicykey, 
                               kvmtciodd_policykey)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETPOLICYKEYFROMTCSERVICE:
        if(!kvmtcio_copyResultandqueue(pent, kvmtciodd_policykeyType, kvmtciodd_sizepolicykey, 
                               kvmtciodd_policykey)) {
            fRet= false;
        }
        break;

      case TCSERVICEGETOSHASHFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICEGETOSHASHFROMAPP, 
                            TCSERVICEGETOSHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETOSHASHFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICEGETOSHASHFROMAPP, 
                        TCSERVICEGETOSHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      // forward to service or app as appropriate
      case TCSERVICEGETOSCREDSFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICEGETOSCREDSFROMAPP, 
                            TCSERVICEGETOSCREDSFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETOSCREDSFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICEGETOSCREDSFROMAPP, 
                        TCSERVICEGETOSCREDSFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICESEALFORFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICESEALFORFROMAPP, 
                            TCSERVICESEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICESEALFORFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICESEALFORFROMAPP, 
                        TCSERVICESEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEUNSEALFORFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICEUNSEALFORFROMAPP, 
                            TCSERVICEUNSEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEUNSEALFORFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICEUNSEALFORFROMAPP, 
                        TCSERVICEUNSEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEATTESTFORFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICEATTESTFORFROMAPP, 
                            TCSERVICEATTESTFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEATTESTFORFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICEATTESTFORFROMAPP, 
                        TCSERVICEATTESTFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICESTARTAPPFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICESTARTAPPFROMAPP,
                            TCSERVICESTARTAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICESTARTAPPFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICESTARTAPPFROMAPP, 
                        TCSERVICESTARTAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICETERMINATEAPPFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICETERMINATEAPPFROMAPP,
                            TCSERVICETERMINATEAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICETERMINATEAPPFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICETERMINATEAPPFROMAPP, 
                        TCSERVICETERMINATEAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEGETPROGHASHFROMAPP:
        if(!kvmtcio_queueforService(pent, TCSERVICEGETPROGHASHFROMAPP, 
                            TCSERVICEGETPROGHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETPROGHASHFROMTCSERVICE:
        if(!kvmtcio_queueforApp(pent, TCSERVICEGETPROGHASHFROMAPP, 
                        TCSERVICEGETPROGHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICETERMINATE:
        if(!kvmtcio_queueforService(pent, TCSERVICETERMINATE, TCSERVICETERMINATE)) {
            fRet= false;
        }
        break;

      case TCSERVICESERVICEHELLO:
      case TCSERVICESERVICEGOODBYE:
      default:
        fRet= false;
        break;
    }

    return fRet;
}


// ------------------------------------------------------------------------------


int kvmtciodd_open(struct inode *inode, struct file *filp)
{
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: open called\n");
#endif
    if(kvmtciodd_serviceInitialized==0) {
        if(current->pid>0) {
            kvmtciodd_servicepid= current->pid;
            kvmtciodd_serviceInitialized= 1;
#ifdef TESTDEVICE
            printk(KERN_DEBUG "kvmtciodd: expected server pid is %d\n", kvmtciodd_servicepid);
#endif
        }
        else {
            printk(KERN_DEBUG "kvmtciodd: bad server\n");
            return -ERESTARTSYS;
        }
    }

    if((filp->f_flags & O_ACCMODE)==O_WRONLY) {
        if(down_interruptible(&kvmtciodd_device->sem))
            return -ERESTARTSYS;
        up(&kvmtciodd_device->sem);
    }

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: open complete\n");
#endif
    return 0;
}


int kvmtciodd_close(struct inode *inode, struct file *filp)
{
    int                 pid= current->pid;
    struct kvmtciodd_Qent* pent= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: close called %d\n", current->pid);
#endif

    // make sure q's don't have entries with this pid
    if(down_interruptible(&kvmtciodd_reqserviceqsem)==0)  {
        for(;;) {
            pent= kvmtciodd_findQentbypid(kvmtciodd_reqserviceq, pid);
            if(pent==NULL)
                break;
            if(pent->m_data!=NULL) {
                memset(pent->m_data, 0, pent->m_sizedata);
                kfree(pent->m_data);
            }
            pent->m_data= NULL;
            kvmtciodd_removeQent(&kvmtciodd_reqserviceq, pent); 
            pent= NULL;
        }
        up(&kvmtciodd_reqserviceqsem);
    }
    if(down_interruptible(&kvmtciodd_resserviceqsem)==0)  {
        for(;;) {
            pent= kvmtciodd_findQentbypid(kvmtciodd_resserviceq, pid);
            if(pent==NULL)
                break;
            if(pent->m_data!=NULL) {
                memset(pent->m_data, 0, pent->m_sizedata);
                kfree(pent->m_data);
            }
            pent->m_data= NULL;
            kvmtciodd_removeQent(&kvmtciodd_resserviceq, pent); 
            pent= NULL;
        }
        up(&kvmtciodd_resserviceqsem);
    }
    
    if (kvmtciodd_servicepid != pid) {
      kvmtcio_sendTerminate(kvmtciodd_servicepid, pid);
    } else {
      kvmtciodd_serviceInitialized = 0;

      // make sure q's don't have any entries, since kvmtciodd is not initialized
      if(down_interruptible(&kvmtciodd_reqserviceqsem)==0)  {
	kvmtciodd_clearQent(&kvmtciodd_reqserviceq);
        up(&kvmtciodd_reqserviceqsem);
      }
      if(down_interruptible(&kvmtciodd_resserviceqsem)==0)  {
	kvmtciodd_clearQent(&kvmtciodd_resserviceq);
        up(&kvmtciodd_resserviceqsem);
      }
    }
    
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: close complete %d\n", pid);
#endif
    return 1;
}


ssize_t kvmtciodd_read(struct file *filp, char __user *buf, size_t count,
                    loff_t *f_pos)
{
    struct kvmtciodd_dev*  dev= kvmtciodd_device;
    ssize_t             retval= 0;
    int                 pid= current->pid;
    struct kvmtciodd_Qent* pent= NULL;

    if (!kvmtciodd_serviceInitialized) {
      return -EFAULT;
    }

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: read %d, privdata: %08lx, pid: %d\n", 
            (int)count, (long int)dev, pid);
#endif

    // if something is on the response queue, fill buffer, otherwise wait
     for(;;) {
        if(down_interruptible(&kvmtciodd_resserviceqsem)==0) {
#ifdef TESTDEVICE
            printk(KERN_DEBUG "kvmtciodd: read looking on response queue for %d\n",
                    pid);
#endif
            pent= kvmtciodd_findQentbypid(kvmtciodd_resserviceq, pid);
            up(&kvmtciodd_resserviceqsem);
        }
        if(pent!=NULL)
            break;

#ifdef TESTDEVICE
        printk(KERN_DEBUG "kvmtciodd: read, waiting on responses in %d\n", pid);
#endif
#if 0
        wait_event_interruptible(dev->waitq, kvmtciodd_resserviceq!=NULL);
#else
        wait_event_timeout(dev->waitq, kvmtciodd_resserviceq!=NULL, TIMEOUT);
#endif
#ifdef TESTDEVICE1
        printk(KERN_DEBUG "kvmtciodd: read, returned from wait in %d\n", pid); 
#endif
    }

#ifdef TESTDEVICE1
    printk(KERN_DEBUG "kvmtciodd: copying buffer for %d\n", pid);
#endif
    if(down_interruptible(&dev->sem))
        return -ERESTARTSYS;

    if(pent->m_sizedata<=count) {
        if(copy_to_user(buf, pent->m_data, pent->m_sizedata)) {
            retval= -EFAULT;
        }
        retval= pent->m_sizedata;
    }
    else {
        retval= -EFAULT;
    }

    if(down_interruptible(&kvmtciodd_resserviceqsem)==0) {
        kvmtciodd_removeQent(&kvmtciodd_resserviceq, pent);
    
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
    printk(KERN_DEBUG "kvmtciodd: read complete for %d\n", pid);
#endif
    return retval;
}


ssize_t kvmtciodd_write(struct file *filp, const char __user *buf, size_t count,
                     loff_t *f_pos)
{
    struct kvmtciodd_dev*      dev= kvmtciodd_device;
    ssize_t                 retval= -ENOMEM;
    byte*                   databuf= NULL;
    struct kvmtciodd_Qent*     pent= NULL;
    tcBuffer*               pCBuf= NULL;
    int                     pid= current->pid;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: write %d for %d\n", (int)count, pid);
#endif
    if(down_interruptible(&dev->sem)) {
        return -ERESTARTSYS;
    }

    if (!kvmtciodd_serviceInitialized) {
      retval = -EFAULT;
      goto out;
    }

    // add to kvmtciodd_reqserviceQ then process
    if(count<sizeof(tcBuffer)) {
        retval= -EFAULT;
        goto out;
    }

    databuf= (byte*) kmalloc(count, GFP_KERNEL);
    if(databuf==NULL) {
        retval= -EFAULT;
        goto out;
    }

    if(copy_from_user(databuf, buf, count)) {
        retval= -EFAULT;
        goto out;
    }

    // make tcheader authoritative
    pCBuf= (tcBuffer*) databuf;
    pCBuf->m_procid= pid;
    if(pid!=kvmtciodd_servicepid)
        pCBuf->m_origprocid= pid;

    pent= kvmtciodd_makeQent(pid, count, databuf, NULL);
    if(pent==NULL) {
        retval= -EFAULT;
        goto out;
    }

    if(down_interruptible(&kvmtciodd_reqserviceqsem)) {
        retval= -ERESTARTSYS;
        goto out;
    }

#ifdef TESTDEVICE1
    printk(KERN_DEBUG "kvmtciodd: write, appending entry\n");
    kvmtcio_printcmdbuffer(pent->m_data);
#endif
    kvmtciodd_appendQent(&kvmtciodd_reqserviceq, pent);
    up(&kvmtciodd_reqserviceqsem);
    retval= count;

out:
    up(&dev->sem);

    if(retval>=0)
        while(kvmtciodd_processService());

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: about to call wake up in %d\n", pid);
#endif
#if 0
    wake_up_interruptible(&(dev->waitq));
#else
    wake_up(&(dev->waitq));
#endif
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: write complete for %d\n", pid);
#endif
    return retval;
}


// --------------------------------------------------------------------


// The cleanup function must handle initialization failures.
void kvmtciodd_cleanup(void)
{
    dev_t       devno= MKDEV(kvmtciodd_major, kvmtciodd_minor);

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: cleanup started\n");
#endif
    // Get rid of dev entries
    if(kvmtciodd_device) {
      cdev_del(&kvmtciodd_device->cdev);
      kfree(kvmtciodd_device);
    }

    if(pclass!=NULL && pdevice!=NULL) {
        device_destroy(pclass, MKDEV(kvmtciodd_major,0));
        pdevice= NULL;
    }
    if(pclass!=NULL) {
        class_destroy(pclass);
        pclass= NULL;
    }

    kvmtciodd_serviceInitialized = 0;

    // cleanup_module isn't called if registering failed
    unregister_chrdev_region(devno, kvmtciodd_nr_devs);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: cleanup complete\n");
#endif
}

// Set up the char_dev structure for this device.
void kvmtciodd_setup_cdev(struct kvmtciodd_dev *dev, int index)
{
    int err, devno;
    
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: setup cdev started\n");
#endif
    devno= MKDEV(kvmtciodd_major, kvmtciodd_minor+index);
    cdev_init(&dev->cdev, &kvmtciodd_fops);
    dev->cdev.owner= THIS_MODULE;
    dev->cdev.ops= &kvmtciodd_fops;
    err= cdev_add (&dev->cdev, devno, 1);
    if(err)
        printk(KERN_NOTICE "Error %d adding kvmtciodd %d", err, index);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: setup cdev complete, devno is %08x\n", devno);
#endif
}


int kvmtciodd_init(void)
{
    int     result;
    dev_t   dev= 0;

    if(kvmtciodd_major) {
        // static registration
        dev= MKDEV(kvmtciodd_major, kvmtciodd_minor);
        result= register_chrdev_region(dev, kvmtciodd_nr_devs, "kvmtciodd");
    } 
    else {
        // dynamic registration
        result= alloc_chrdev_region(&dev, kvmtciodd_minor, kvmtciodd_nr_devs, "kvmtciodd");
        kvmtciodd_major= MAJOR(dev);
    }
    if(result<0) {
        printk(KERN_WARNING "kvmtciodd: can't get major %d\n", kvmtciodd_major);
        return result;
    }

    pclass= class_create(THIS_MODULE, "kvmtciodd");
    if(pclass==NULL)
        goto fail;
    pdevice= device_create(pclass, NULL, MKDEV(kvmtciodd_major,0), NULL, "kvmtciodd0");
    if(pdevice==NULL)
        goto fail;

    kvmtciodd_device= kmalloc(sizeof(struct kvmtciodd_dev), GFP_KERNEL);
    if(!kvmtciodd_device) {
        result= -ENOMEM;
        goto fail;
    }
    memset(kvmtciodd_device, 0, sizeof(struct kvmtciodd_dev));

    // initialize service Q semaphore
    sema_init(&kvmtciodd_reqserviceqsem, 1);
    sema_init(&kvmtciodd_resserviceqsem, 1);

    // Initialize the device
    sema_init(&kvmtciodd_device->sem, 1);
    init_waitqueue_head(&kvmtciodd_device->waitq);
    kvmtciodd_setup_cdev(kvmtciodd_device, 0);

#ifdef TESTDEVICE
    printk(KERN_DEBUG "kvmtciodd: kvmtciodd_init complete\n");
#endif
    return 0;

fail:
    kvmtciodd_cleanup();
    return result;
}

// expose the device structure itself to the KVM vmdd code
EXPORT_SYMBOL(kvmtciodd_device);

// expose a variable to check whether or not the service is initialized
EXPORT_SYMBOL(kvmtciodd_serviceInitialized);

// expose the queues and their semaphores to the KVM hypercall handlers
EXPORT_SYMBOL(kvmtciodd_reqserviceqsem);
EXPORT_SYMBOL(kvmtciodd_resserviceqsem);
EXPORT_SYMBOL(kvmtciodd_reqserviceq);
EXPORT_SYMBOL(kvmtciodd_resserviceq);

EXPORT_SYMBOL(kvmtciodd_processService);

#ifdef LINUXLICENSED
MODULE_LICENSE("GPL");
module_init(kvmtciodd_init);
module_exit(kvmtciodd_cleanup);
#endif


// ------------------------------------------------------------------------------


