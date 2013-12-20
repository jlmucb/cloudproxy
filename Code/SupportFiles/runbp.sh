#
#    This starts the original bidProxy
#

echo "bidProxy"
cd ~/jlmcrypt
echo "Starting keyNegoServer"
./keyNegoServer.exe &
sleep 2s
echo "Starting bidServer"
./tcLaunch.exe -LinuxHost ./bidServer.exe
sleep 2s
echo "Starting bidClient"
./tcLaunch.exe -LinuxHost ./bidClient.exe
sleep 1s
ps aux | fgrep "keyNegoServer"
echo "Starting bidClient"
./tcLaunch.exe -LinuxHost ./sellerClient.exe
echo "You may want to kill keyNegoServer"

