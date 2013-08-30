//  File: tcioddDD.h
//      Defines for tciodd device driver
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//  Some portion Copyright (c), 2012, Intel Corporation.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.
//  Some portions of this source code is subject to the license set forth below.

/*
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


// --------------------------------------------------------------------


#ifndef _TCIODD_H_
#define _TCIODD_H_

#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#define TCIODD_MAJOR 100
#ifndef TCIODD_MAJOR
#define TCIODD_MAJOR 0           // dynamic major by default
#endif

#ifndef byte
typedef unsigned char byte;
#endif


// Q's for read and write
struct tciodd_Qent {
    int                 m_pid;
    byte*               m_data;
    int                 m_sizedata;
    // struct tciodd_Qent* m_next;
    void*               m_next;
};

extern  struct tciodd_Qent* tciodd_makeQent(int pid, int sizedata, byte* data, 
                                                struct tciodd_Qent* next);
extern  void   tciodd_deleteQent(struct tciodd_Qent* pent);
extern  int    tciodd_insertQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent);
extern  int    tciodd_appendQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent);
extern  int    tciodd_removeQent(struct tciodd_Qent** phead, struct tciodd_Qent* pent);
extern  struct tciodd_Qent* tciodd_findQentbypid(struct tciodd_Qent* head, int pid);
void tciodd_clearQent(struct tciodd_Qent** phead);


struct tciodd_dev {
    wait_queue_head_t   waitq;
    struct semaphore    sem;           // mutual exclusion semaphore 
    struct cdev         cdev;          // char device structure  
};


#define TYPE(minor)     (((minor) >> 4) & 0xf)
#define NUM(minor)      ((minor) & 0xf)


#define JIFTIMEOUT 100


extern int      tciodd_major;     
extern int      tciodd_nr_devs;

ssize_t         tciodd_read(struct file *filp, char __user *buf, size_t count,
                    loff_t *f_pos);
ssize_t         tciodd_write(struct file *filp, const char __user *buf, size_t count,
                     loff_t *f_pos);
extern int      tciodd_ioctl(struct inode *inode, struct file *filp,
                     unsigned cmd, unsigned long arg);
int      tciodd_open(struct inode *inode, struct file *filp);
int      tciodd_close(struct inode *inode, struct file *filp);
bool tciodd_processService(void);

struct tcBuffer {
    int                 m_procid;
    u32                 m_reqID;
    u32                 m_reqSize;
    u32                 m_ustatus;
    int                 m_origprocid;
};
typedef struct tcBuffer tcBuffer;


//  tcService - status values
#define TCIOSUCCESS             0
#define TCIOFAILED              1
#define TCIONOSERVICE           2
#define TCIONOMEM               3
#define TCIONOSERVICERESOURCE   4
#define TCIONOTPM               5

#endif


// --------------------------------------------------------------------


