OBJROOT=~/jlmcrypt

BUILD_TARGETS=keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest
TARGETS=$(BUILD_TARGETS) clean
.PHONY: $(TARGETS)

all: $(BUILD_TARGETS)

tcService:
	$(MAKE) -C tcService -f tcService.mak

fileServer:
	$(MAKE) -C fileProxy -f fileServer.mak

fileClient:
	$(MAKE) -C fileProxy -f fileClient.mak

keyNegoServer:
	$(MAKE) -C keyNegoServer -f keyNegoServer.mak

cryptUtility:
	$(MAKE) -C cryptUtility -f cryptUtility.mak

cryptotest:
	$(MAKE) -C Test -f cryptotest.mak

aesspeed:
	$(MAKE) -C Test -f aesspeed.mak

#rsaspeedtest:
#	$(MAKE) -C Test -f rsaspeedtest.mak

clean:
	rm -f $(OBJROOT)/*objects/*
	rm -f $(OBJROOT)/*.o
	rm -f $(OBJROOT)/keyNegoServer.exe
	rm -f $(OBJROOT)/tcService.exe
	rm -f $(OBJROOT)/fileServer.exe
	rm -f $(OBJROOT)/fileClient.exe
#	rm -f $(OBJROOT)/rsaspeedtest.exe
	rm -f $(OBJROOT)/cryptUtility.exe
	rm -f $(OBJROOT)/aesspeedtest.exe
