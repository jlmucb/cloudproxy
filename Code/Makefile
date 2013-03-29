OBJROOT=~/jlmcrypt

BUILD_TARGETS=keyNegoServer tcService authServer authClient bidServer bidClient filServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest
TARGETS=$(BUILD_TARGETS) clean
.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

tcService:
	$(MAKE) -C tcService -f oldtcService.mak

bidServer:
	$(MAKE) -C bidProxy -f bidServer.mak

bidClient:
	$(MAKE) -C bidProxy -f bidClient.mak

authServer:
	$(MAKE) -C authProxy -f authServer.mak

authClient:
	$(MAKE) -C authProxy -f authClient.mak

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
	rm -f $(OBJROOT)/authServer.exe
	rm -f $(OBJROOT)/authClient.exe
	rm -f $(OBJROOT)/bidServer.exe
	rm -f $(OBJROOT)/bidClient.exe
	rm -f $(OBJROOT)/fileServer.exe
	rm -f $(OBJROOT)/fileClient.exe
	rm -f $(OBJROOT)/rsaspeedtest.exe
	rm -f $(OBJROOT)/cryptUtility.exe
	rm -f $(OBJROOT)/aesspeedtest.exe
