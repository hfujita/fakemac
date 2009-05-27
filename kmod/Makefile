ifneq ($(KERNELRELEASE),)
obj-m := fakemac.o
else
KERNELDIR := /lib/modules/`uname -r`/build

modules:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

.c.o:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@


endif
