sudo bash
cd ~/jlmcrypt
/etc/init.d/trousers stop
chown jlm /dev/tpm0
insmod tcioDD.ko
chmod 0777 /dev/tcioDD0
exit
./tcService.exe &
./keyNegoServer.exe
sleep 2s
./fileServer.exe -initProg
sleep 2s
./fileClient.exe -initProg

