#
#    This is run as root to Init the Guest's
#    tcService
#
chmod 0777 /dev/*tcio*
./keyNegoServer.exe &
./tcKvmGuestOsService.exe -initKeys

