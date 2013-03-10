#
cd ~/fpDev/fileProxy/Code/cryptUtility
make -f cryptUtility.mak
cd ~/fpDev/fileProxy/Code/tcService
make -f tcService.mak
cd ~/fpDev/fileProxy/Code/keyNegoServer
make -f keyNegoServer.mak
cd ~/fpDev/fileProxy/Code/fileProxy
make -f fileClient.mak
make -f fileServer.mak
cd ~/fpDev/fileProxy/Code/Test
make -f cryptotest.mak
make -f aesspeedtest.mak
make -f rsaspeedtest.mak
