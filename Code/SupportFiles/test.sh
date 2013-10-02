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
./tcLaunch.exe -LinuxHost ./fileServer.exe
sleep 2s
tcLaunch.exe -LinuxHost ./fileClient.exe
sleep 5s

#this is the standalone test in the kvm host
sudo bash
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
exit
cd ~/jlmcrypt
./keyNegoServer.exe #in one window
./tcKvmService.exe -initKeys # in another window
cd ~/jlmcrypt
./tcKvmHostService.exe &
sudo bash
chown jlm /var/lib/libvirt/images/*.img
./tcLaunch.exe -KVMLinux KvmTestGuest d051d4f5-c216-1aaf-9d51-320bcfc45124 /home/jlm/jlmcrypt/vms/vmlinuz-3.5.0-23-generic /home/jlm/jlmcrypt/vms/initrd.img-3.5.0-23-generic /var/lib/libvirt/images/KvmTestGuest.img

ssh jlm@192.168.122.244
sftp
put exes.tar

In GuestOS:
sudo bash
/etc/init.d/trousers stop
chmod 0777 /dev/*tcio*
exit
cd ~/jlmcrypt
./keyNegoServer.exe 
./tcKvmGuestOsService.exe -initKeys


