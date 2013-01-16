#
cd /dev
mknod tcioDD0 c 100 0
cd ~/jlmcrypt
insmod tcioDD.ko
./tcService.exe &
./fileServer.exe &
./fileClient.exe &
rmmod tcioDD.ko

