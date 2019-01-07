# virtio-mac80211
Virtio Mac80211 front end driver implementation

This is a purely academic attempt to implement virtio based softmac IEEE 802.11 device.

virtio IEEE 802.11 backend device implementation is part of,
https://github.com/ra7narajm/qemu.git
airport:
        -net hub implementation
virtio-mac80211:
        -virtio IEEE802.11 backend driver

how-to:
1. qemu guest creation (backend driver),
        AP mode: [-netdev airport,terminalid=aid0,id=x0,mode=ap -device virtio-wifi,netdev=x0,mac=aa:bb:cc:xx:yy:zz]
        STA mode: [-netdev airport,terminalid=aid0,id=x0,mode=sta -device virtio-wifi,netdev=x0,mac=aa:bb:cc:xx:yy:zz]
2. within qemu guest (frontend driver),
        insert virtio_mac80211 kernel module, run hostapd / wpa_supplicant as per guest mode.

The driver heavily borrows (copies!!) from mac80211_hwsim and virtio_net drivers.
Authors for respective modules,
 mac80211_hwsim
 Copyright (c) 2008, Jouni Malinen <j@w1.fi>
 Copyright (c) 2011, Javier Lopez <jlopex@gmail.com>

 virtio_net
 Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation

TODO: <too many to list at this point>
1. ditching mode in guest creation (that way guest can choose mode at runtime)
2.

Alternate implementation:
	1. adding dummy wireless NIC using mac80211_hwsim
	2. enabling monitor mode (RadioTAP) on dummy interface,
	3. redirecting (ie. tunnel) traffic over ethernet NIC.

-
Ratnaraj Mirgal
<ratnaraj.mirgal@gmail.com>

