OBJROOT=~/jlmcrypt

BUILD_TARGETS=keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest
TARGETS=$(BUILD_TARGETS) clean
.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

tcService:
	$(MAKE) -C newtcService -f tcService.mak

fileServer:
	$(MAKE) -C newfileProxy -f fileServer.mak

fileClient:
	$(MAKE) -C newfileProxy -f fileClient.mak

keyNegoServer:
	$(MAKE) -C newkeyNegoServer -f keyNegoServer.mak

cryptUtility:
	$(MAKE) -C newcryptUtility -f cryptUtility.mak

cryptotest:
	$(MAKE) -C Test -f cryptotest.mak

aesspeed:
	$(MAKE) -C Test -f aesspeed.mak

#rsaspeedtest:
#	$(MAKE) -C Test -f rsaspeedtest.mak

clean:
	rm -f $(OBJROOT)/*objects/*
	rm -f $(OBJROOT)/*.o
	rm -f $(OBJROOT)/newkeyNegoServer.exe
	rm -f $(OBJROOT)/newtcService.exe
	rm -f $(OBJROOT)/newfileServer.exe
	rm -f $(OBJROOT)/newfileClient.exe
#	rm -f $(OBJROOT)/rsaspeedtest.exe
	rm -f $(OBJROOT)/cryptUtility.exe
	rm -f $(OBJROOT)/aesspeedtest.exe
