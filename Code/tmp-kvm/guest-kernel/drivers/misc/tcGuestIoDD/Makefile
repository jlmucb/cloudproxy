ifndef KREL
	KREL = $(shell uname -r)
endif

KDIR ?= /lib/modules/$(KREL)/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
