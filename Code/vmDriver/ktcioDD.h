/*
 * File ktcioDD.h - 
 *	Header file for virtualized trusted service device driver. 
 *	This is heavily based on the tcioDD.h driver code.
 */
#ifndef _KTCIODD_H_
#define _KTCIODD_H_

#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#define KTCIODD_MAJOR 100
#ifndef KTCIODD_MAJOR
#define KTCIODD_MAJOR 0           // dynamic major by default
#endif

#ifndef KTCIODD_NR_DEVS
#define KTCIODD_NR_DEVS 1
#endif

struct ktciodd_dev {
    struct cdev         kdev;          // char device structure  
};
extern int ktciodd_major;     

ssize_t ktciodd_read(struct file *filp, char __user *buf, size_t count,
                    loff_t *f_pos);

ssize_t ktciodd_write(struct file *filp, const char __user *buf, size_t count,
                     loff_t *f_pos);

//int ktciodd_ioctl(struct inode *inode, struct file *filp, unsigned cmd, unsigned long arg); 

#endif
