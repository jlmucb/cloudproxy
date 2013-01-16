KERNELRELEASE=/usr/share/doc/linux-3.2.0
DEBUG=y
obj-m += tcioDD.o
LDDINC=/usr/share/doc/linux-3.2.0/include
JMCRYPT=/home/jlm/jlm/MySrc/fileProxy/Code/jlmcrypto
JMSERVICE=/home/jlm/jlm/MySrc/fileProxy/Code/tcService
JMTYPES=/home/jlm/jlm/MySrc/fileProxy/Code/commonCode
# -I$(JMCRYPT) -I$(JMSERVICE) -I$(JMTYPES)
all:
	make -C /lib/modules/$(shell uname -r)/build -I$(JMCRYPT) -I$(JMSERVICE) -I$(JMTYPES) -I$(LDDINC) M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

