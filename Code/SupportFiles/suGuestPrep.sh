#
#    This is run as root to prepare the KVMGuest
#    and start the service.  TODO: take argumments
#
/etc/init.d/trousers stop
chown jlm /dev/tpm0
chmod 0777 /dev/*tcio*
./tcKvmGuestOsService.exe -initKeys

