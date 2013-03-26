OBJROOT=~/jlmcrypt

.PHONY: keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest clean

all: keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest

tcService:
	$(MAKE) -C tcService -f oldtcService.mak

fileServer:
	$(MAKE) -C fileProxy -f oldfileServer.mak

fileClient:
	$(MAKE) -C fileProxy -f oldfileClient.mak

keyNegoServer:
	$(MAKE) -C keyNegoServer -f oldkeyNegoServer.mak

cryptUtility:
	$(MAKE) -C cryptUtility -f oldcryptUtility.mak

cryptotest:
	$(MAKE) -C Test -f cryptotest.mak

aesspeed:
	$(MAKE) -C Test -f aesspeed.mak

rsaspeedtest:
	$(MAKE) -C Test -f rsaspeedtest.mak

clean:
	rm -f $(OBJROOT)/*objects/*
	rm -f $(OBJROOT)/*.o
	rm -f $(OBJROOT)/keyNegoServer.exe
	rm -f $(OBJROOT)/tcService.exe
	rm -f $(OBJROOT)/fileServer.exe
	rm -f $(OBJROOT)/fileClient.exe
	rm -f $(OBJROOT)/rsaspeedtest.exe
	rm -f $(OBJROOT)/cryptUtility.exe
	rm -f $(OBJROOT)/aesspeedtest.exe
