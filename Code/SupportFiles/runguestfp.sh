#
#    This starts the guest fileProxy
#

echo "guest fileProxy"
cd ~/jlmcrypt
echo "Starting keyNegoServer"
./keyNegoServer.exe &
echo "Starting guest fileServer"
./tcLaunch.exe -LinuxGuest ./guestfileServer.exe
sleep 2s
echo "Starting guest fileClient"
./tcLaunch.exe -LinuxGuest ./guestfileClient.exe
sleep 2s
ps aux | fgrep "keyNegoServer"
echo "You may want to kill keyNegoServer"

