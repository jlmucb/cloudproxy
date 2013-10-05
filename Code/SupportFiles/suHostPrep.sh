#
#    This is run as root to prepare the KVMHost
#    and start the service.  TODO: take argumments
#

echo "Fixing permissions"
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
chown jlm /var/lib/libvirt/images/*.img
virt-manager
cd ~/jlmcrypt
echo "Starting Service"
./tcKvmHostService.exe &
sleep 3s
echo "Launching KvmGuest"
./tcLaunch.exe -KVMLinux KvmTestGuest d051d4f5-c216-1aaf-9d51-320bcfc45124 /home/jlm/jlmcrypt/vms/vmlinuz-3.5.0-23-generic /home/jlm/jlmcrypt/vms/initrd.img-3.5.0-23-generic /var/lib/libvirt/images/KvmTestGuest.img



