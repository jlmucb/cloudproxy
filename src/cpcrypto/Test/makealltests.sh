#
make -f ../cpcryptolib.mak clean
make -f aesspeed.mak clean
make -f cryptotest.mak clean
make -f mpTest.mak clean
make -f rsaspeedtest.mak clean
make -f sha256speedtest.mak clean

make -f ../cpcryptolib.mak
make -f aesspeed.mak
make -f cryptotest.mak
make -f mpTest.mak
make -f rsaspeedtest.mak
make -f sha256speedtest.mak
