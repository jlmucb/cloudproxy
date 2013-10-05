sudo bash
cd ~/jlmcrypt
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/tcioDD0
# only do the following if the drivers is not loaded
insmod tcioDD.ko
./keyNegoServer.exe
./tcService.exe -initKeys
./tcService.exe &
sleep 2s
./tcLaunch.exe -LinuxHost ./fileServer.exe
sleep 2s
tcLaunch.exe -LinuxHost ./fileClient.exe
sleep 5s

#this is the standalone test in the kvm host
sudo bash
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
chown jlm /var/lib/libvirt/images/*.img
exit
cd ~/jlmcrypt
./tcKvmHostService.exe &
./tcLaunch.exe -KVMLinux KvmTestGuest d051d4f5-c216-1aaf-9d51-320bcfc45124 /home/jlm/jlmcrypt/vms/vmlinuz-3.5.0-23-generic /home/jlm/jlmcrypt/vms/initrd.img-3.5.0-23-generic /var/lib/libvirt/images/KvmTestGuest.img

address is obtained from ifconfig -a in guest.
ssh jlm@192.168.122.98
sftp
put exes.tar
It GuestOS:
start ssh
chmod 0777 /dev/*tcio*
cd ~/jlmcrypt
./keyNegoServer.exe 
./tcKvmGuestOsService.exe -initKeys


