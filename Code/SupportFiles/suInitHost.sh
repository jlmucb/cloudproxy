#
#    This is run as root to prepare the KVMHost
#    and init tcservice.  TODO: take argumments
#

/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
chown jlm /var/lib/libvirt/images/*.img
su jlm
cd ~/jlmcrypt
echo "Starting keyNegoServer"
./keyNegoServer.exe &
echo "Starting Service"
./tcKvmHostService.exe -initKeys
ps aux | fgrep "keyNegoServer"
echo "You might want to kill keyNegoServer"

