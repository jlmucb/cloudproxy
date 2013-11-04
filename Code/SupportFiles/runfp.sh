#
#    This starts the original fileProxy
#

echo "fileProxy"
cd ~/jlmcrypt
echo "Starting keyNegoServer"
./keyNegoServer.exe &
sleep 2s
echo "Starting fileServer"
./tcLaunch.exe -LinuxHost ./fileServer.exe
sleep 2s
echo "Starting fileClient"
./tcLaunch.exe -LinuxHost ./fileClient.exe
sleep 1s
echo "Starting fileClienta"
./tcLaunch.exe -LinuxHost ./fileClienta.exe
sleep 1s
echo "Starting fileClientb"
./tcLaunch.exe -LinuxHost ./fileClientb.exe
sleep 1s
echo "Starting fileClientc"
./tcLaunch.exe -LinuxHost ./fileClientc.exe
ps aux | fgrep "keyNegoServer"
echo "You may want to kill keyNegoServer"

