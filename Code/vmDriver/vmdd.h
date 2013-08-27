/*
 *  vmdd.h - all the process ioctls to control the kernel module
 */
#include <linux/ioctl.h>

#define DEVICE_FILE_NAME "ktcioDD"

#define IOCTLREAD 1
#define IOCTLWRITE 2
#define IOCTLGETDATA 3

int vm_register(int pid, int size, char* data);
int vm_unregister(int pid);
int ioctl_read(int pid, int size, char* data);
int ioctl_write(int pid, int size, char* data);
byte* ioctl_getData(int pid);
