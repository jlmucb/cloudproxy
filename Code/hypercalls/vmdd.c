#include <asm/page.h>
#include <linux/kvm_host.h>
#include <asm/vmdd.h>
#include <linux/types.h>

#define TCDEVNAME "/dev/tcioDD0"
//check if the tcService is running.  If yes, connect to it; else start the service and then connect.

int vmdd_connect(struct pid *vmpid);
int vmdd_disconnect(struct pid *vmpid);
int vmdd_read(struct pid *vmpid, struct file *fp, char *buf, ssize_t count, loff_t *pos);
int vmdd_write(struct pid *vmpid, struct file *fp, char *buf, ssize_t count, loff_t *pos);

int tcdd_fd;
int vmdd_connect(struct pid *vmpid) {

	int ret = 0;
	tcdd_fd = open(TCDEVNAME, O_RDWR);
	if (tcdd_fd < 0) {
		printk(KERN_ERROR, "Unable to open tcioDD \n");
		ret = -1;
		return ret;
	}

/* TODO: register the VM with tcioDD*/
	return ret;
}//end vmdd_connect

int vmdd_disconnect(struct pid *vmpid) {
	int ret = 0;

	ret = close(tcdd_fd);

	return ret;
}//end vmdd_disconnect

int vmdd_read(struct pid *vmpid, struct file *fp, char *buf, ssize_t count, loff_t *pos) {

	int ret = 0;
	if (tcdd_fd > 0) {
		return read(tcdd_fd, buf, count);
	}
	return ret;
}//end vmdd_read

int vmdd_write(struct pid *vmpid, struct file *fp, char *buf, ssize_t count, loff_t *pos) {
	int ret = 0;
	if (tcdd_fd > 0) {
		return write(tcdd_fd, buf, count);
	}
}//vmdd_write
