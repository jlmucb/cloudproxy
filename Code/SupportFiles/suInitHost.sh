#
#    This is run as root to prepare the KVMHost
#    and init tcservice.  TODO: take argumments
#

/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
chown jlm /var/lib/libvirt/images/*.img
cd ~/jlmcrypt
./tcKvmHostService.exe -initKeys


