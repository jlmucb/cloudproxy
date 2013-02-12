OBJROOT = /home/tmroeder/jlmcrypt

.PHONY: keyNego tcServ fileS fileC clean

all: tcServ fileS fileC keyNego
tcServ:
	$(MAKE) -C tcService -f tcService.mak

fileS:
	$(MAKE) -C fileProxy -f fileServer.mak

fileC:
	$(MAKE) -C fileProxy -f fileClient.mak

keyNego:
	$(MAKE) -C keyNegoServer -f keyNegoServer.mak


clean:
	rm -f $(OBJROOT)/*objects/*
	rm -f $(OBJROOT)/keyNegoServer.exe
	rm -f $(OBJROOT)/tcService.exe
	rm -f $(OBJROOT)/fileServer.exe
	rm -f $(OBJROOT)/fileClient.exe
