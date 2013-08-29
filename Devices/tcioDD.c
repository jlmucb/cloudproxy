//
//  File: tcioDD.c
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

#include "tcioDD.h"
#include "tciohdr.h"
#include "tcServiceCodes.h"
#include "algs.h"

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
/* #include <asm/system.h> */
#include <asm/uaccess.h>


#define TESTDEVICE
#define TIMEOUT 8000

#ifndef SHA256HASHSIZE
#define SHA256HASHSIZE 32
#endif


extern ssize_t  tciodd_read(struct file *filp, char __user *buf, size_t count,
                            loff_t *f_pos);
extern ssize_t  tciodd_write(struct file *filp, const char __user *buf, size_t count,
                             loff_t *f_pos);
extern int      tciodd_open(struct inode *inode, struct file *filp);
extern int      tciodd_close(struct inode *inode, struct file *filp);


// ----------------------------------------------------------------------------


unsigned    tciodd_serviceInitialized= 0;
int         tciodd_servicepid= 0;


int         tciodd_major=   TCIODD_MAJOR;
int         tciodd_minor=   0;
int         tciodd_nr_devs= TCIODD_NR_DEVS;


module_param(tciodd_major, int, S_IRUGO);
module_param(tciodd_minor, int, S_IRUGO);
module_param(tciodd_nr_devs, int, S_IRUGO);


struct tciodd_dev*  tciodd_devices;

struct file_operations tciodd_fops= {
    .owner=    THIS_MODULE,
    .read=     tciodd_read,
    .write=    tciodd_write,
    .open=     tciodd_open,
    .release=  tciodd_close,
};


//  Read and write buffers have the following format:
//      tcBuffer header || data

struct semaphore    tciodd_reqserviceqsem; 
struct tciodd_Qent* tciodd_reqserviceq= NULL;
struct semaphore    tciodd_resserviceqsem; 
struct tciodd_Qent* tciodd_resserviceq= NULL;


//
//  For udev and dynamic allocation of device
static struct class*    pclass= NULL;
static struct device*   pdevice= NULL;



// ----------------------------------------------------------------------------


#ifdef TESTDEVICE


// These are unsafe but they are only used for debug

void printcmdbuffer(byte* pB)
{
    tcBuffer* pC= (tcBuffer*) pB;
    pB+= sizeof(tcBuffer);
    printk(KERN_DEBUG "procid: %d, origprocid: %d, req: %d, size: %d\n",
           pC->m_procid, pC->m_origprocid, pC->m_reqID, pC->m_reqSize);
}


void printent(struct tciodd_Qent* pE)
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


void printlist(struct tciodd_Qent* pE)
{
    int     n= 0;

    while(pE!=NULL) {
        printent(pE);
        pE= (struct tciodd_Qent*) pE->m_next;
        n++;
    }
    printk(KERN_DEBUG "  %d list elements\n", n);
}


void printrequestQ(void)
{
    printk(KERN_DEBUG "tcioDD: request list\n");
    printlist(tciodd_reqserviceq);
}


void printresponseQ(void)
{
    printk(KERN_DEBUG "tcioDD: response list\n");
    printlist(tciodd_resserviceq);
}


#endif


// ------------------------------------------------------------------------------


struct tciodd_Qent* tciodd_makeQent(int pid, int sizedata, byte* data, 
                                    struct tciodd_Qent* next)
{
    struct tciodd_Qent* pent= NULL;
    void*               area= kmalloc(sizeof(struct tciodd_Qent), GFP_KERNEL);

    if(area==NULL)
        return NULL;
    pent= (struct tciodd_Qent*)area;
    pent->m_pid= current->pid;
    pent->m_data= data;
    pent->m_sizedata= sizedata;
    pent->m_next= NULL;
    return pent;
}


void tciodd_deleteQent(struct tciodd_Qent* pent)
{
    memset((void*)pent, 0, sizeof(struct tciodd_Qent));
    kfree((void*)pent);
    return;
}


int  tciodd_insertQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent)
{
    pent->m_next= *phead;
    *phead= pent;
    return 1;
}


int  tciodd_appendQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent)
{
    struct tciodd_Qent* p;

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


int  tciodd_removeQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent)
{
    struct tciodd_Qent* pPrev= NULL;
    struct tciodd_Qent* p= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: removeQent\n");
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

void tciodd_clearQent(struct tciodd_Qent** phead)
{
  struct tciodd_Qent* cur = NULL;
  if (phead == NULL) return;

  cur = *phead;
  while (cur != NULL) {
    // remove the current head
    *phead = cur->m_next;

    tciodd_deleteQent(cur);
    cur = *phead;
  }
}

struct tciodd_Qent* tciodd_findQentbypid(struct tciodd_Qent* head, int pid)
{
    struct tciodd_Qent* p= head;

    while(p!=NULL) {
        if(p->m_pid==pid)
            return p;
        p= p->m_next;
    }
    return NULL;
}


// --------------------------------------------------------------------


bool sendTerminate(int procid, int origprocid)
{
    tcBuffer*           newhdr= NULL;
    int                 newdatasize;
    byte*               newdata;
    struct tciodd_Qent* pent= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: sendTerminate(%d, %d)\n", procid, origprocid);
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
    pent= tciodd_makeQent(tciodd_servicepid, newdatasize, newdata, NULL);
    if(pent==NULL)
        return false;

    if(down_interruptible(&tciodd_reqserviceqsem)) 
        return false;
    tciodd_appendQent(&tciodd_reqserviceq, pent);
    up(&tciodd_reqserviceqsem);
    return true;
}


bool copyResultandqueue(struct tciodd_Qent* pent, u32 type, int sizebuf, byte* buf)
//  Copy from buf to new ent
{
    int         n= 0;
    tcBuffer*   hdr= (tcBuffer*)pent->m_data;
    tcBuffer*   newhdr= NULL;
    int         newdatasize;
    byte*       newdata;
    int         m= 0;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: copyResultandqueue\n");
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

    if(down_interruptible(&tciodd_resserviceqsem)) 
        return false;
    n= tciodd_appendQent(&tciodd_resserviceq, pent);
    up(&tciodd_resserviceqsem);
    return true;
}


bool queueforService(struct tciodd_Qent* pent, u32 appReq, u32 serviceReq)
{
    int         n;
    tcBuffer*   hdr= (tcBuffer*)pent->m_data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: queueforService appCode: %d serviceCode: %d\n",
            appReq, serviceReq);
#endif
    // adjust and append to waitq
    if(down_interruptible(&tciodd_resserviceqsem)) 
        return false;
    hdr->m_origprocid= hdr->m_procid;
    hdr->m_procid= tciodd_servicepid;
    hdr->m_reqID= serviceReq;
    hdr->m_ustatus= TCIOSUCCESS;
    pent->m_pid= tciodd_servicepid;
    n= tciodd_appendQent(&tciodd_resserviceq, pent);
    up(&tciodd_resserviceqsem);
    return true;
}


bool queueforApp(struct tciodd_Qent* pent, u32 appReq, u32 serviceReq)
{
    tcBuffer*   hdr= (tcBuffer*) pent->m_data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: queueforApp appCode: %d serviceCode: %d\n",
            appReq, serviceReq);
#endif
    // adjust and append to waitq
    if(down_interruptible(&tciodd_resserviceqsem))
        return false;
    hdr->m_procid= hdr->m_origprocid;
    hdr->m_reqID= appReq;
    pent->m_pid= hdr->m_origprocid;
    tciodd_appendQent(&tciodd_resserviceq, pent);
    up(&tciodd_resserviceqsem);
    return true;
}


bool tciodd_processService(void)
//  Take entry off request queue, service it and put it on response queue
{
    int                 n= 0;
    struct tciodd_Qent* pent= NULL;
    tcBuffer*           hdr= NULL;
    int                 datasize= 0;
    byte*               data= NULL;
    bool                fRet= true;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: processService started\n");
    printrequestQ(); printresponseQ();
#endif
    if(down_interruptible(&tciodd_reqserviceqsem)) 
        return false;
    pent= tciodd_reqserviceq;
    n= tciodd_removeQent(&tciodd_reqserviceq, pent);
    up(&tciodd_reqserviceqsem);

    if(n<=0 || pent==NULL)
        return false;

    datasize= pent->m_sizedata;
    data= pent->m_data;
    hdr= (tcBuffer*)data;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: processService got ent from reqQ %d, size: %d\n", 
           pent->m_pid, pent->m_sizedata);
    printcmdbuffer(pent->m_data);
#endif

    // don't forget to wake up reading processes
    switch(hdr->m_reqID) {

      // For first four, no need to go to service
      case TCSERVICEGETPOLICYKEYFROMAPP:
        if(!copyResultandqueue(pent, tciodd_policykeyType, tciodd_sizepolicykey, 
                               tciodd_policykey)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETPOLICYKEYFROMTCSERVICE:
        if(!copyResultandqueue(pent, tciodd_policykeyType, tciodd_sizepolicykey, 
                               tciodd_policykey)) {
            fRet= false;
        }
        break;

      case TCSERVICEGETOSHASHFROMAPP:
        if(!queueforService(pent, TCSERVICEGETOSHASHFROMAPP, 
                            TCSERVICEGETOSHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETOSHASHFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICEGETOSHASHFROMAPP, 
                        TCSERVICEGETOSHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      // forward to service or app as appropriate
      case TCSERVICEGETOSCREDSFROMAPP:
        if(!queueforService(pent, TCSERVICEGETOSCREDSFROMAPP, 
                            TCSERVICEGETOSCREDSFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETOSCREDSFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICEGETOSCREDSFROMAPP, 
                        TCSERVICEGETOSCREDSFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICESEALFORFROMAPP:
        if(!queueforService(pent, TCSERVICESEALFORFROMAPP, 
                            TCSERVICESEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICESEALFORFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICESEALFORFROMAPP, 
                        TCSERVICESEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEUNSEALFORFROMAPP:
        if(!queueforService(pent, TCSERVICEUNSEALFORFROMAPP, 
                            TCSERVICEUNSEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEUNSEALFORFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICEUNSEALFORFROMAPP, 
                        TCSERVICEUNSEALFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEATTESTFORFROMAPP:
        if(!queueforService(pent, TCSERVICEATTESTFORFROMAPP, 
                            TCSERVICEATTESTFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEATTESTFORFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICEATTESTFORFROMAPP, 
                        TCSERVICEATTESTFORFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICESTARTAPPFROMAPP:
        if(!queueforService(pent, TCSERVICESTARTAPPFROMAPP,
                            TCSERVICESTARTAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICESTARTAPPFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICESTARTAPPFROMAPP, 
                        TCSERVICESTARTAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICETERMINATEAPPFROMAPP:
        if(!queueforService(pent, TCSERVICETERMINATEAPPFROMAPP,
                            TCSERVICETERMINATEAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICETERMINATEAPPFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICETERMINATEAPPFROMAPP, 
                        TCSERVICETERMINATEAPPFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICEGETPROGHASHFROMAPP:
        if(!queueforService(pent, TCSERVICEGETPROGHASHFROMAPP, 
                            TCSERVICEGETPROGHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;
      case TCSERVICEGETPROGHASHFROMTCSERVICE:
        if(!queueforApp(pent, TCSERVICEGETPROGHASHFROMAPP, 
                        TCSERVICEGETPROGHASHFROMTCSERVICE)) {
            fRet= false;
        }
        break;

      case TCSERVICETERMINATE:
        if(!queueforService(pent, TCSERVICETERMINATE, TCSERVICETERMINATE)) {
            fRet= false;
        }
        break;

      default:
        fRet= false;
        break;
    }

    return fRet;
}


// ------------------------------------------------------------------------------


int tciodd_open(struct inode *inode, struct file *filp)
{
    struct tciodd_dev*  dev= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: open called\n");
#endif
    if(tciodd_serviceInitialized==0) {
        if(current->pid>0) {
            tciodd_servicepid= current->pid;
            tciodd_serviceInitialized= 1;
#ifdef TESTDEVICE
            printk(KERN_DEBUG "tcioDD: expected server pid is %d\n", tciodd_servicepid);
#endif
        }
        else {
            printk(KERN_DEBUG "tcioDD: bad server\n");
            return -ERESTARTSYS;
        }
    }

    dev= container_of(inode->i_cdev, struct tciodd_dev, cdev);
    filp->private_data= dev; 

    if((filp->f_flags & O_ACCMODE)==O_WRONLY) {
        if(down_interruptible(&dev->sem))
            return -ERESTARTSYS;
        up(&dev->sem);
    }

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: open complete\n");
#endif
    return 0;
}


int tciodd_close(struct inode *inode, struct file *filp)
{
    int                 pid= current->pid;
    struct tciodd_Qent* pent= NULL;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: close called %d\n", current->pid);
#endif

    // make sure q's don't have entries with this pid
    if(down_interruptible(&tciodd_reqserviceqsem)==0)  {
        for(;;) {
            pent= tciodd_findQentbypid(tciodd_reqserviceq, pid);
            if(pent==NULL)
                break;
            if(pent->m_data!=NULL) {
                memset(pent->m_data, 0, pent->m_sizedata);
                kfree(pent->m_data);
            }
            pent->m_data= NULL;
            tciodd_removeQent(&tciodd_reqserviceq, pent); 
            pent= NULL;
        }
        up(&tciodd_reqserviceqsem);
    }
    if(down_interruptible(&tciodd_resserviceqsem)==0)  {
        for(;;) {
            pent= tciodd_findQentbypid(tciodd_resserviceq, pid);
            if(pent==NULL)
                break;
            if(pent->m_data!=NULL) {
                memset(pent->m_data, 0, pent->m_sizedata);
                kfree(pent->m_data);
            }
            pent->m_data= NULL;
            tciodd_removeQent(&tciodd_resserviceq, pent); 
            pent= NULL;
        }
        up(&tciodd_resserviceqsem);
    }
    
    if (tciodd_servicepid != pid) {
      sendTerminate(tciodd_servicepid, pid);
    } else {
      tciodd_serviceInitialized = 0;

      // make sure q's don't have any entries, since tciodd is not initialized
      if(down_interruptible(&tciodd_reqserviceqsem)==0)  {
	tciodd_clearQent(&tciodd_reqserviceq);
        up(&tciodd_reqserviceqsem);
      }
      if(down_interruptible(&tciodd_resserviceqsem)==0)  {
	tciodd_clearQent(&tciodd_resserviceq);
        up(&tciodd_resserviceqsem);
      }
    }
    
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: close complete %d\n", pid);
#endif
    return 1;
}


ssize_t tciodd_read(struct file *filp, char __user *buf, size_t count,
                    loff_t *f_pos)
{
    struct tciodd_dev*  dev= filp->private_data; 
    ssize_t             retval= 0;
    int                 pid= current->pid;
    struct tciodd_Qent* pent= NULL;

    if (!tciodd_serviceInitialized) {
      return -EFAULT;
    }

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: read %d, privdata: %08lx, pid: %d\n", 
            (int)count, (long int)dev, pid);
#endif

    // if something is on the response queue, fill buffer, otherwise wait
     for(;;) {
        if(down_interruptible(&tciodd_resserviceqsem)==0) {
#ifdef TESTDEVICE
            printk(KERN_DEBUG "tcioDD: read looking on response queue for %d\n",
                    pid);
#endif
            pent= tciodd_findQentbypid(tciodd_resserviceq, pid);
            up(&tciodd_resserviceqsem);
        }
        if(pent!=NULL)
            break;

#ifdef TESTDEVICE
        printk(KERN_DEBUG "tcioDD: read, waiting on responses in %d\n", pid);
#endif
#if 0
        wait_event_interruptible(dev->waitq, tciodd_resserviceq!=NULL);
#else
        wait_event_timeout(dev->waitq, tciodd_resserviceq!=NULL, TIMEOUT);
#endif
#ifdef TESTDEVICE1
        printk(KERN_DEBUG "tcioDD: read, returned from wait in %d\n", pid); 
#endif
    }

#ifdef TESTDEVICE1
    printk(KERN_DEBUG "tcioDD: copying buffer for %d\n", pid);
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

    if(down_interruptible(&tciodd_resserviceqsem)==0) {
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


ssize_t tciodd_write(struct file *filp, const char __user *buf, size_t count,
                     loff_t *f_pos)
{
    struct tciodd_dev*      dev= filp->private_data;
    ssize_t                 retval= -ENOMEM;
    byte*                   databuf= NULL;
    struct tciodd_Qent*     pent= NULL;
    tcBuffer*               pCBuf= NULL;
    int                     pid= current->pid;

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: write %d for %d\n", (int)count, pid);
#endif
    if(down_interruptible(&dev->sem)) {
        return -ERESTARTSYS;
    }

    if (!tciodd_serviceInitialized) {
      retval = -EFAULT;
      goto out;
    }

    // add to tciodd_reqserviceQ then process
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
    if(pid!=tciodd_servicepid)
        pCBuf->m_origprocid= pid;

    pent= tciodd_makeQent(pid, count, databuf, NULL);
    if(pent==NULL) {
        retval= -EFAULT;
        goto out;
    }

    if(down_interruptible(&tciodd_reqserviceqsem)) {
        retval= -ERESTARTSYS;
        goto out;
    }

#ifdef TESTDEVICE1
    printk(KERN_DEBUG "tcioDD: write, appending entry\n");
    printcmdbuffer(pent->m_data);
#endif
    tciodd_appendQent(&tciodd_reqserviceq, pent);
    up(&tciodd_reqserviceqsem);
    retval= count;

out:
    up(&dev->sem);

    if(retval>=0)
        while(tciodd_processService());

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: about to call wake up in %d\n", pid);
#endif
#if 0
    wake_up_interruptible(&(dev->waitq));
#else
    wake_up(&(dev->waitq));
#endif
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: write complete for %d\n", pid);
#endif
    return retval;
}


// --------------------------------------------------------------------


// The cleanup function must handle initialization failures.
void tciodd_cleanup(void)
{
    int         i;
    dev_t       devno= MKDEV(tciodd_major, tciodd_minor);

#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: cleanup started\n");
#endif
    // Get rid of dev entries
    if(tciodd_devices) {
        for(i= 0; i<tciodd_nr_devs; i++) {
            cdev_del(&tciodd_devices[i].cdev);
        }
        kfree(tciodd_devices);
    }

    if(pclass!=NULL && pdevice!=NULL) {
        device_destroy(pclass, MKDEV(tciodd_major,0));
        pdevice= NULL;
    }
    if(pclass!=NULL) {
        class_destroy(pclass);
        pclass= NULL;
    }

    tciodd_serviceInitialized = 0;

    // cleanup_module isn't called if registering failed
    unregister_chrdev_region(devno, tciodd_nr_devs);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: cleanup complete\n");
#endif
}


// Set up the char_dev structure for this device.
void tciodd_setup_cdev(struct tciodd_dev *dev, int index)
{
    int err, devno;
    
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: setup cdev started\n");
#endif
    devno= MKDEV(tciodd_major, tciodd_minor+index);
    cdev_init(&dev->cdev, &tciodd_fops);
    dev->cdev.owner= THIS_MODULE;
    dev->cdev.ops= &tciodd_fops;
    err= cdev_add (&dev->cdev, devno, 1);
    if(err)
        printk(KERN_NOTICE "Error %d adding tciodd %d", err, index);
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: setup cdev complete, devno is %08x\n", devno);
#endif
}


int tciodd_init(void)
{
    int     result, i;
    dev_t   dev= 0;

    if(tciodd_major) {
        // static registration
        dev= MKDEV(tciodd_major, tciodd_minor);
        result= register_chrdev_region(dev, tciodd_nr_devs, "tciodd");
    } 
    else {
        // dynamic registration
        result= alloc_chrdev_region(&dev, tciodd_minor, tciodd_nr_devs, "tciodd");
        tciodd_major= MAJOR(dev);
    }
    if(result<0) {
        printk(KERN_WARNING "tciodd: can't get major %d\n", tciodd_major);
        return result;
    }

    pclass= class_create(THIS_MODULE, "tcioDD");
    if(pclass==NULL)
        goto fail;
    pdevice= device_create(pclass, NULL, MKDEV(tciodd_major,0), NULL, "tcioDD0");
    if(pdevice==NULL)
        goto fail;

    tciodd_devices= kmalloc(tciodd_nr_devs*sizeof(struct tciodd_dev), GFP_KERNEL);
    if(!tciodd_devices) {
        result= -ENOMEM;
        goto fail;
    }
    memset(tciodd_devices, 0, tciodd_nr_devs*sizeof(struct tciodd_dev));

    // initialize service Q semaphore
    sema_init(&tciodd_reqserviceqsem, 1);
    sema_init(&tciodd_resserviceqsem, 1);

    // Initialize each device. 
    for(i= 0; i<tciodd_nr_devs; i++) {
        sema_init(&tciodd_devices[i].sem, 1);
        init_waitqueue_head(&tciodd_devices[i].waitq);
        tciodd_setup_cdev(&tciodd_devices[i], i);
    }
#ifdef TESTDEVICE
    printk(KERN_DEBUG "tcioDD: tciodd_init complete\n");
#endif
    return 0;

fail:
    tciodd_cleanup();
    return result;
}

#ifdef LINUXLICENSED
MODULE_LICENSE("GPL");
module_init(tciodd_init);
module_exit(tciodd_cleanup);
#endif


// ------------------------------------------------------------------------------


