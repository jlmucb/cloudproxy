sudo bash
/etc/init.d/trousers stop
chown jlm /dev/tpm0
cd ~/jlmcrypt
# only do the following if the drivers is not loaded
insmod tcioDD.ko
chmod 0777 /dev/tcioDD0
./keyNegoServer.exe
./tcService.exe -initKeys
./tcService.exe &
sleep 2s
./tcLaunch.exe -LinuxGuest ./fileServer.exe
sleep 2s
tcLaunch.exe -LinuxGuest ./fileClient.exe
sleep 5s

#this is the standalone test in the kvm host
./tcKvmService.exe &
./tcLaunch.exe -KVMHost Test1 /home/jlm/jlmcrypt/vms/vmlinuz-3.5.0-23-generic /home/jlm/jlmcrypt/vms/initrd.img-3.5.0-23-generic /home/jlm/jlmcrypt/vms/Test1.img

