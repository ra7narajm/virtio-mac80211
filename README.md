## virtio-mac80211
**Virtio Mac 802.11 front end driver implementation**

NOTE: The repo now includes wifi-medium (server) implementation

This is a purely academic attempt to implement virtio based softmac IEEE 802.11 device.

**virtio IEEE 802.11 backend device implementation is part of Qemu v3.1.0 included in the repo**

Qemu backend components,
1. airport:
	- portal to wifi-medium
2. virtio-mac80211:
	- virtio IEEE802.11 backend driver

how-to:
1. wifi-medium,
	**wifimedium -i XX -d -l file.log**
	_option i refers to terminal-id used by qemu termid netdev option_

2. qemu guest creation (backend driver),
        **-netdev airport,termid=123,id=x0 -device virtio-wifi,netdev=x0,mac=aa:bb:cc:xx:yy:zz**

3. within qemu guest (frontend driver),
	**insmod virtio_mac80211.ko**
        _now run hostapd / wpa_supplicant as per guest mode_

The frontend driver heavily borrows (copies!!) from mac80211_hwsim and virtio_net drivers.
Authors for respective modules,

- mac80211_hwsim
	- Copyright (c) 2008, Jouni Malinen <j@w1.fi>
	- Copyright (c) 2011, Javier Lopez <jlopex@gmail.com>

- virtio_net
	- Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation

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


-Ratnaraj Mirgal
