#
cd ~//fileProxy/Code/cryptUtility
make -f cryptUtility.mak
cd ~//fileProxy/Code/tcService
make -f tcService.mak
cd ~//fileProxy/Code/keyNegoServer
make -f keyNegoServer.mak
cd ~//fileProxy/Code/fileProxy
make -f fileClient.mak
make -f fileServer.mak
cd ~//fileProxy/Code/Test
make -f cryptotest.mak
make -f aesspeedtest.mak
make -f rsaspeedtest.mak
