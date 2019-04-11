#ifndef _UAPI_LINUX_VIRTIO_MAC80211_H
#define _UAPI_LINUX_VIRTIO_MAC80211_H
/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * TODO A copy of this header to kept in qemu/include/standard-headers/linux/
 */

#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#include <linux/if_ether.h>
#ifdef __KERNEL__
#include <linux/ieee80211.h>
#include <net/mac80211.h>
#endif //__KERNEL__

#define GOOD_MAC80211_PACKET_LEN	IEEE80211_MAX_RTS_THRESHOLD	//2352
//#define VIRTMAC80211_RX_PAD 		(NET_IP_ALIGN + NET_SKB_PAD)
#define VIRTMAC80211_RX_PAD 		(NET_SKB_PAD)	//ref. rtl8180

#define VIRTIO_MAC80211_BUF_LEN		SKB_DATA_ALIGN(VIRTMAC80211_RX_PAD + GOOD_MAC80211_PACKET_LEN \
						+ SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define MAX_MAC80211_HLEN		(sizeof(struct ieee80211_hdr))

/* feature bitmap for virtio mac80211 */
#define VIRTIO_MAC80211_F_MTU        3       /* Initial MTU advice */
#define VIRTIO_MAC80211_F_MAC        5       /* Host has given MAC address. */
#define VIRTIO_MAC80211_F_CTRL_RX    18      /* Control channel RX mode support */
#define VIRTIO_MAC80211_F_STATUS     16	     /* virtio_mac80211_config: status support */

/* status */
#define VIRTIO_MAC80211_S_LINK_UP	1    /* Link is up */
#define VIRTIO_MAC80211_S_ANNOUNCE	2    /* Announcement is needed */

struct __vwlan_config {
	__u8 mac[ETH_ALEN];
	__u16 status;
	__u16 max_virtqueue_pairs;
	__u16 mtu;
	uint32_t speed;
	uint8_t duplex;
} __attribute__((packed));

#endif //_UAPI_LINUX_VIRTIO_MAC80211_H
