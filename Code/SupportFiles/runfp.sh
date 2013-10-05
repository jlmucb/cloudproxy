#
#    This starts the original fileProxy
#

echo "fileProxy"
cd ~/jlmcrypt
echo "Starting keyNegoServer"
./keyNegoServer.exe &
echo "Starting fileServer"
./tcLaunch.exe -LinuxHost ./fileServer.exe
sleep 2s
echo "Starting fileClient"
./tcLaunch.exe -LinuxHost ./fileClient.exe
sleep 2s
ps aux | fgrep "keyNegoServer"
echo "You may want to kill keyNegoServer"

