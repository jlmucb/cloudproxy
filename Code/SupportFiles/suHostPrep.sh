#
#    This is run as root to prepare the KVMHost
#    and start the service.  TODO: take argumments
#

echo "Fixing permissions"
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
chown jlm /var/lib/libvirt/images/*.img
su jlm
virt-manager
cd ~/jlmcrypt
echo "Starting Service"
./tcKvmHostService.exe &
sleep 3s
echo "Launching KvmGuest"
./tcLaunch.exe -KVMLinux KvmTestGuest  \
  /home/jlm/jlmcrypt/vms/KvmTestGuestMeasuredTemplate.xml \
  /home/jlm/jlmcrypt/vms/vmlinuz \
  /home/jlm/jlmcrypt/vms/initrd.img \
  /var/lib/libvirt/images/KvmTestGuest.img

