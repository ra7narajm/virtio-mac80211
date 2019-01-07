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

/*
 * buffer size for virtqueue format as follows,
 * virtqueue buf size VIRTIO_MAC80211_BUF_LEN
 * buf headroom: VIRTMAC80211_RX_PAD
 * max packet size: GOOD_MAC80211_PACKET_LEN
 * tail: skb_shared_info 
 */

#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <net/mac80211.h>

#define GOOD_MAC80211_PACKET_LEN	IEEE80211_MAX_RTS_THRESHOLD	//2352
//#define VIRTMAC80211_RX_PAD 		(NET_IP_ALIGN + NET_SKB_PAD)
#define VIRTMAC80211_RX_PAD 		(NET_SKB_PAD)	//ref. rtl8180

#define VIRTIO_MAC80211_BUF_LEN		SKB_DATA_ALIGN(VIRTMAC80211_RX_PAD + GOOD_MAC80211_PACKET_LEN \
						+ SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define MAX_MAC80211_HLEN		(sizeof(struct ieee80211_hdr))

/* feature bitmap for virtio mac80211 */
#define VIRTIO_MAC80211_F_CSUM       0       /* Host handles pkts w/ partial csum */
#define VIRTIO_MAC80211_F_GUEST_CSUM 1       /* Guest handles pkts w/ partial csum */
#define VIRTIO_MAC80211_F_CTRL_GUEST_OFFLOADS 2 /* Dynamic offload configuration. */
#define VIRTIO_MAC80211_F_MTU        3       /* Initial MTU advice */
#define VIRTIO_MAC80211_F_MAC        5       /* Host has given MAC address. */
#define VIRTIO_MAC80211_F_GUEST_TSO4 7       /* Guest can handle TSOv4 in. */
#define VIRTIO_MAC80211_F_GUEST_TSO6 8       /* Guest can handle TSOv6 in. */
#define VIRTIO_MAC80211_F_GUEST_ECN  9       /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_MAC80211_F_GUEST_UFO  10      /* Guest can handle UFO in. */
#define VIRTIO_MAC80211_F_HOST_TSO4  11      /* Host can handle TSOv4 in. */
#define VIRTIO_MAC80211_F_HOST_TSO6  12      /* Host can handle TSOv6 in. */
#define VIRTIO_MAC80211_F_HOST_ECN   13      /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_MAC80211_F_HOST_UFO   14      /* Host can handle UFO in. */
#define VIRTIO_MAC80211_F_MRG_RXBUF  15      /* Host can merge receive buffers. */
#define VIRTIO_MAC80211_F_STATUS     16      /* virtio_net_config.status available */
#define VIRTIO_MAC80211_F_CTRL_VQ    17      /* Control channel available */
#define VIRTIO_MAC80211_F_CTRL_RX    18      /* Control channel RX mode support */
#define VIRTIO_MAC80211_F_CTRL_VLAN  19      /* Control channel VLAN filtering */
#define VIRTIO_MAC80211_F_CTRL_RX_EXTRA  20  /* Extra RX mode control support */
#define VIRTIO_MAC80211_F_GUEST_ANNOUNCE 21  /* Guest can announce device on the
                                              * network */
#define VIRTIO_MAC80211_F_MQ		 22  /* multiqueue support */

/* status */
#define VIRTIO_MAC80211_S_LINK_UP	1    /* Link is up */
#define VIRTIO_MAC80211_S_ANNOUNCE	2    /* Announcement is needed */

struct virtio_mac80211_config {
	/* The config defining mac address (if VIRTIO_MAC80211_F_MAC) */
	__u8 mac[ETH_ALEN];
	/* See VIRTIO_MAC80211_F_STATUS and VIRTIO_MAC80211_S_* above */
	__u16 status;
	/* Maximum number of each of transmit and receive queues;
	 * see VIRTIO_MAC80211_F_MQ and VIRTIO_NET_CTRL_MQ.
	 * Legal values are between 1 and 0x8000
	 */
	__u16 max_virtqueue_pairs;
	/* Default maximum transmit unit advice */
	__u16 mtu;
} __attribute__((packed));

/* TODO GSO and CSUM features, and virtio_net_hdr equivalent struct to support
 * header which comes first in SG list
 */

/**
 * enum hwsim_tx_control_flags - flags to describe transmission info/status
 *
 * These flags are used to give the wmediumd extra information in order to
 * modify its behavior for each frame
 *
 * @HWSIM_TX_CTL_REQ_TX_STATUS: require TX status callback for this frame.
 * @HWSIM_TX_CTL_NO_ACK: tell the wmediumd not to wait for an ack
 * @HWSIM_TX_STAT_ACK: Frame was acknowledged
 *
 */
enum hwsim_tx_control_flags {
	HWSIM_TX_CTL_REQ_TX_STATUS		= BIT(0),
	HWSIM_TX_CTL_NO_ACK			= BIT(1),
	HWSIM_TX_STAT_ACK			= BIT(2),
};

/**
 * DOC: Frame transmission/registration support
 *
 * Frame transmission and registration support exists to allow userspace
 * entities such as wmediumd to receive and process all broadcasted
 * frames from a mac80211_hwsim radio device.
 *
 * This allow user space applications to decide if the frame should be
 * dropped or not and implement a wireless medium simulator at user space.
 *
 * Registration is done by sending a register message to the driver and
 * will be automatically unregistered if the user application doesn't
 * responds to sent frames.
 * Once registered the user application has to take responsibility of
 * broadcasting the frames to all listening mac80211_hwsim radio
 * interfaces.
 *
 * For more technical details, see the corresponding command descriptions
 * below.
 */

/**
 * enum hwsim_commands - supported hwsim commands
 *
 * @HWSIM_CMD_UNSPEC: unspecified command to catch errors
 *
 * @HWSIM_CMD_REGISTER: request to register and received all broadcasted
 *	frames by any mac80211_hwsim radio device.
 * @HWSIM_CMD_FRAME: send/receive a broadcasted frame from/to kernel/user
 *	space, uses:
 *	%HWSIM_ATTR_ADDR_TRANSMITTER, %HWSIM_ATTR_ADDR_RECEIVER,
 *	%HWSIM_ATTR_FRAME, %HWSIM_ATTR_FLAGS, %HWSIM_ATTR_RX_RATE,
 *	%HWSIM_ATTR_SIGNAL, %HWSIM_ATTR_COOKIE, %HWSIM_ATTR_FREQ (optional)
 * @HWSIM_CMD_TX_INFO_FRAME: Transmission info report from user space to
 *	kernel, uses:
 *	%HWSIM_ATTR_ADDR_TRANSMITTER, %HWSIM_ATTR_FLAGS,
 *	%HWSIM_ATTR_TX_INFO, %HWSIM_ATTR_SIGNAL, %HWSIM_ATTR_COOKIE
 * @HWSIM_CMD_NEW_RADIO: create a new radio with the given parameters,
 *	returns the radio ID (>= 0) or negative on errors, if successful
 *	then multicast the result
 * @HWSIM_CMD_DEL_RADIO: destroy a radio, reply is multicasted
 * @HWSIM_CMD_GET_RADIO: fetch information about existing radios, uses:
 *	%HWSIM_ATTR_RADIO_ID
 * @__HWSIM_CMD_MAX: enum limit
 */
enum {
	HWSIM_CMD_UNSPEC,
	HWSIM_CMD_REGISTER,
	HWSIM_CMD_FRAME,
	HWSIM_CMD_TX_INFO_FRAME,
	HWSIM_CMD_NEW_RADIO,
	HWSIM_CMD_DEL_RADIO,
	HWSIM_CMD_GET_RADIO,
	__HWSIM_CMD_MAX,
};
#define HWSIM_CMD_MAX (_HWSIM_CMD_MAX - 1)

#define HWSIM_CMD_CREATE_RADIO   HWSIM_CMD_NEW_RADIO
#define HWSIM_CMD_DESTROY_RADIO  HWSIM_CMD_DEL_RADIO

/**
 * enum hwsim_attrs - hwsim netlink attributes
 *
 * @HWSIM_ATTR_UNSPEC: unspecified attribute to catch errors
 *
 * @HWSIM_ATTR_ADDR_RECEIVER: MAC address of the radio device that
 *	the frame is broadcasted to
 * @HWSIM_ATTR_ADDR_TRANSMITTER: MAC address of the radio device that
 *	the frame was broadcasted from
 * @HWSIM_ATTR_FRAME: Data array
 * @HWSIM_ATTR_FLAGS: mac80211 transmission flags, used to process
	properly the frame at user space
 * @HWSIM_ATTR_RX_RATE: estimated rx rate index for this frame at user
	space
 * @HWSIM_ATTR_SIGNAL: estimated RX signal for this frame at user
	space
 * @HWSIM_ATTR_TX_INFO: ieee80211_tx_rate array
 * @HWSIM_ATTR_COOKIE: sk_buff cookie to identify the frame
 * @HWSIM_ATTR_CHANNELS: u32 attribute used with the %HWSIM_CMD_CREATE_RADIO
 *	command giving the number of channels supported by the new radio
 * @HWSIM_ATTR_RADIO_ID: u32 attribute used with %HWSIM_CMD_DESTROY_RADIO
 *	only to destroy a radio
 * @HWSIM_ATTR_REG_HINT_ALPHA2: alpha2 for regulatoro driver hint
 *	(nla string, length 2)
 * @HWSIM_ATTR_REG_CUSTOM_REG: custom regulatory domain index (u32 attribute)
 * @HWSIM_ATTR_REG_STRICT_REG: request REGULATORY_STRICT_REG (flag attribute)
 * @HWSIM_ATTR_SUPPORT_P2P_DEVICE: support P2P Device virtual interface (flag)
 * @HWSIM_ATTR_USE_CHANCTX: used with the %HWSIM_CMD_CREATE_RADIO
 *	command to force use of channel contexts even when only a
 *	single channel is supported
 * @HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE: used with the %HWSIM_CMD_CREATE_RADIO
 *	command to force radio removal when process that created the radio dies
 * @HWSIM_ATTR_RADIO_NAME: Name of radio, e.g. phy666
 * @HWSIM_ATTR_NO_VIF:  Do not create vif (wlanX) when creating radio.
 * @HWSIM_ATTR_FREQ: Frequency at which packet is transmitted or received.
 * @__HWSIM_ATTR_MAX: enum limit
 */


enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	HWSIM_ATTR_PAD,
	__HWSIM_ATTR_MAX,
};
#define HWSIM_ATTR_MAX (__HWSIM_ATTR_MAX - 1)

/**
 * struct hwsim_tx_rate - rate selection/status
 *
 * @idx: rate index to attempt to send with
 * @count: number of tries in this rate before going to the next rate
 *
 * A value of -1 for @idx indicates an invalid rate and, if used
 * in an array of retry rates, that no more rates should be tried.
 *
 * When used for transmit status reporting, the driver should
 * always report the rate and number of retries used.
 *
 */
struct hwsim_tx_rate {
	s8 idx;
	u8 count;
} __attribute__((packed));

#endif //_UAPI_LINUX_VIRTIO_MAC80211_H
