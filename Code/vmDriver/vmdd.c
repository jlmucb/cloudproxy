/*
 *  vmdd.c - all the process ioctls to control the kernel module
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */

/* 
 * Functions for the ioctl calls 
 */

int vm_register(int pid, int size, char* data){
}

int vm_unregister(int pid) {
}

ssize_t ioctl_read(int devfd, int size, char* data) {
}

ssize_t ioctl_write(int devfd, int size, char* data) {
}

char* ioctl_getData(int pid) {
}
