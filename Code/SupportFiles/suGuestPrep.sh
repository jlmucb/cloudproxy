#
#    This is run as root to prepare the KVMGuest
#    and init the service.  TODO: take argumments
#
chmod 0777 /dev/*tcio*
su jlm
echo "Starting Service"
./tcKvmGuestOsService.exe &
