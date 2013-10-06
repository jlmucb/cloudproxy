#
#    This is run as root to Init the Guest's
#    tcService
#
echo "Fixing permissions"
chmod 0777 /dev/*tcio*
su jlm
echo "Starting keyNegoServer"
./keyNegoServer.exe &
echo "Starting Service"
./tcKvmGuestOsService.exe -initKeys
ps aux | fgrep "keyNegoServer"
echo "You may want to kill keyNegoServer"

