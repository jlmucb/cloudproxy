#
cd /dev
mknod tcioDD0 c 100 0
cd ~/jlmcrypt
insmod tcioDD.ko
./tcService.exe &
./keyNegoServer.exe &
./fileServer.exe -initKeys
./fileClient.exe -initKeys
rmmod tcioDD.ko

