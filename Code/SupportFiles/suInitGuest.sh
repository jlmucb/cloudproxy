#
#    This is run as root to Init the Guest's
#    tcService
#

./keyNegoServer.exe &
./tcKvmGuestOsService.exe -initKeys

