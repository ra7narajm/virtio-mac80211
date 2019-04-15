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
	- **insmod virtio_mac80211.ko**
        - _now run hostapd / wpa_supplicant as per guest mode_

The frontend driver heavily borrows (copies!!) from mac80211_hwsim and virtio_net drivers.
In backend netdev (airport) driver is implemented by referring to VDE and hubport drivers.
While, backend device (virtio-mac80211) driver refers to virtio-net, virtio-rng.

- Alternate implementation:
	1. adding dummy wireless NIC using mac80211_hwsim
	2. enabling monitor mode (RadioTAP) on dummy interface,
	3. redirecting (ie. tunnel) traffic over ethernet NIC.

- Topology:

                                      +----------------+            +----------------+
                                      |  vCL1          |            | vCL2           |
                                      |                |            |                |
                                      |    wlan0       |            |    wlan0       |
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
                                                    |    wlan0        |
                                                    |                 |
                                                    |     eth0        |
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

***current status: Qemu code changes in progress***
- Device List,
	- name "virtio-mac80211-device", bus virtio-bus, desc "Virtio MAC 802.11 controller"
	- name "virtio-mac80211-pci", bus PCI

- Qemu guest config,
	- qemu-system-i386 -smp 2 -kernel ./bzImage -m 1G -serial stdio --append "root=/dev/sda rw console=tty0 console=ttyS0,115200" -drive format=raw,file=./rootfs.ext2,index=0,media=disk -boot c -rtc base=localtime **-netdev airport,termid=20,id=x0 -device virtio-mac80211-pci,netdev=x0,mac=52:55:00:d1:55:01** -netdev tap,ifname=tap0,script=no,downscript=no,id=x1 -device virtio-net,netdev=x1,mac=52:55:00:d1:55:02
	- lspci output,
		**00:03.0 Class 0280: 1af4:100a virtio-pci**

-Ratnaraj Mirgal
