## virtio-mac80211
**Virtio Mac 802.11 front end driver implementation**

NOTE: The repo includes wifi-medium (server) implementation.

This is a purely academic attempt to implement virtio based softmac IEEE 802.11 device.

**virtio IEEE 802.11 backend device implementation is part of Qemu v3.1.0 (included in the repo)**
- Qemu configured as follows,
	_(./configure --prefix=/usr --enable-system --enable-linux-user --enable-gcrypt --enable-linux-aio --enable-tpm --enable-tools --enable-kvm --enable-vhost-net --enable-gnutls)_

Qemu backend components,
1. airport:
	- portal to wifi-medium
2. virtio-mac80211:
	- virtio IEEE802.11 backend driver

how-to:
1. wifi-medium,
	- **wifimedium -i XX -d -l file.log**
	- _option i refers to terminal-id used by qemu termid netdev option_

2. qemu guest creation (backend driver),
        - **-netdev airport,termid=123,id=x0 -device virtio-wifi,netdev=x0,mac=aa:bb:cc:xx:yy:zz**

3. within qemu guest (frontend driver),
	- **insmod virtio-mac80211.ko**
	- _now run hostapd / wpa-supplicant as per guest mode_
4. Steps to add frontend driver with buildroot,
	- Currently tested with buildroot-2018.02.4, using buildroot config (misc/qemu_virtio_test_defconfig) and linux config (misc/linux-4.15.config).
	- To build virtio-mac80211 driver module, add this repo as BR2-EXTERNAL package. for example, **make O=./build/vtest BR2-EXTERNAL=~/path/to/virtio-mac80211 menuconfig**

The frontend (Linux) driver is based on mac80211-hwsim and virtio-net drivers.
And Qemu backend netdev (airport) driver is implemented by referring to VDE and hubport drivers.
While, backend device (virtio-mac80211) driver is (mostly) based on virtio-net and virtio-rng.

NOTE: Qemu backend netdev **airport** is only compatible with device **virtio-mac80211**

- Alternate implementation:
	1. adding dummy wireless NIC using mac80211-hwsim
	2. enabling monitor mode (RadioTAP) on dummy interface,
	3. redirecting (ie. tunnel) traffic over ethernet NIC.

- Topology:

			Client VMs (virtio-mac80211 in managed mode)
                                      +----------------+            +----------------+
                                      |  vCL1          |            | vCL2           |
                                      |                |            |                |
                                      |    vwlan0      |            |    vwlan0      |
                                      |   +--------+   |            |   +--------+   |
                                      |   |        |   |            |   |        |   |
                                      +---+---+----+---+            +---+----+---+---+
                                              |                              |
                                              |                              |
                                      +-------+------------------------------+--------+
                                      |                                               |
                                      | Wifi-Medium                                   |
                                      |                                               |
                                      +----------------------+------------------------+
                                                             |
                                                             |
                                                    +----+---+---+----+
                                                    |    |       |    |
                                                    |    +-------+    |
                                                    |     vwlan0      |
                                                    |                 |  Access Point VM
                                                    |     eth0        |  (virtio-mac80211 in AP mode)
                                                    |    +-------+    |
                                                    |    |       |    |
                                                    +-----------------+
                                                         |       |
                                                         +---+---+ tap0
                                                             |
                                                             |
                                                          +--+----------------------+
                                                          |                         |
                                                          | br0                     |
                                                          |                         |
                                                          +---------+---------------+
                                                                    |
                                                                    |   eth0
                                                              +-----+-------+
                                                              |             |
                  +-------------------------------------------+-------------+-----------------------+

***Current status: virtio-mac80211 frontend driver wireless packet path to wifi-medium***
- Qemu Device List,
	- name "virtio-mac80211-device", bus virtio-bus, desc "Virtio MAC 802.11 controller"
	- name "virtio-mac80211-pci", bus PCI

- Qemu guest config,
	- qemu-system-i386 -smp 2 -kernel ./bzImage -m 1G -serial stdio --append "root=/dev/sda rw console=tty0 console=ttyS0,115200" -drive format=raw,file=./rootfs.ext2,index=0,media=disk -boot c -rtc base=localtime **-netdev airport,termid=20,id=x0 -device virtio-mac80211-pci,netdev=x0,mac=52:55:00:d1:55:01** -netdev tap,ifname=tap0,script=no,downscript=no,id=x1 -device virtio-net,netdev=x1,mac=52:55:00:d1:55:02
	- lspci output,
		**00:03.0 Class 0280: 1af4:100a virtio-pci**
```
00:03.0 Network controller [0280]: Red Hat, Inc Device [1af4:100a]
	Subsystem: Red Hat, Inc Device [1af4:000a]
	Kernel driver in use: virtio-pci

# lsmod
Module                  Size  Used by    Tainted: G  
arc4                   16384  2 
virtio_mac80211        24576  0 
mac80211              356352  1 virtio_mac80211
sha256_generic         24576  0 
cfg80211              221184  1 mac80211

4: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 52:55:00:d1:55:01 brd ff:ff:ff:ff:ff:ff

```

-Ratnaraj Mirgal
