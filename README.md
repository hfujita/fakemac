fakemac - make your switch "dumb" hub
==

Author: Hajime Fujita <crisp.fujita@nifty.com>

Introduction
--

This tool hides the real MAC address of your NIC to prevent switch
from learning your address.  When a switch does not have an entry in
its MAC address table, it broadcast a frame to the whole collision
domain (i.e. "flooding" mode).  This is sometimes useful when you are
constructing single IP address cluster based on broadcast-based
mechanism.

This tools is implemented as a Linux kernel module and supports up to kernel 2.6.35.

Build
--

To build the module, type
```
# cd kmod
# make
```

If you want to build a module for a kernel other than currently
running on your machine, use `KERNELDIR` variable to specify the
location of your target kernel.
```
# make KERNELDIR=/path/to/your/kernel
```

Usage
--

To use fakemac, first load the module.
```
# insmod fakemac.ko
```

After the successful loading of the module, you'll see several files
under the `/proc/sys/net/fakemac` directory.

If you want to hide the real MAC address of `eth0`, type the following command:
```
# echo 1 > /proc/sys/net/fakemac/eth0
```

As you may imagine, you can disable fakemac by doing this:
```
# echo 0 > /proc/sys/net/fakemac/eth0
```

By default, fakemac is disabled for all network interfaces.

Acknowledgment
--

The idea of this tool comes from Microsoft Windows Server Network Load Balancing (NLB) multicast feature.

This tool has been developed under the JST CREST "Dependable Operating System for Embedded Systems Aiming at Practical Applications" project.
