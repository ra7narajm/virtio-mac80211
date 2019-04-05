/*
 * Virtio MAC802.11 Network Device
 *	Based on virtio-net device
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_VIRTIO_MAC80211_H
#define QEMU_VIRTIO_MAC80211_H

#include "qemu/units.h"
#include "standard-headers/linux/virtio_mac80211.h"
#include "hw/virtio/virtio.h"

#define TYPE_VIRTIO_MAC80211 "virtio-mac80211-device"
#define VIRTIO_MAC80211_OBJ(obj) \
        OBJECT_CHECK(VirtWifiInfo, (obj), TYPE_VIRTIO_MAC80211)

#define TX_TIMER_INTERVAL 150000 /* 150 us */

/* Limit the number of packets that can be sent via a single flush
 * of the TX queue.  This gives us a guaranteed exit condition and
 * ensures fairness in the io path.  256 conveniently matches the
 * length of the TX queue and shows a good balance of performance
 * and latency. */
#define TX_BURST 256

typedef struct virtio_wlan_conf
{
    uint32_t txtimer;
    int32_t txburst;
    char *tx;
    uint16_t rx_queue_size;
    uint16_t tx_queue_size;
    uint16_t mtu;
    int32_t speed;
    char *duplex_str;
    uint8_t duplex;
} virtio_wlan_conf;

/* Using max buffer size defined in kernel-space */
#define VIRTIO_WLAN_MAX_BUFSIZE		VIRTIO_MAC80211_BUF_LEN

typedef struct VirtWifiQueue {
    VirtQueue *rx_vq;
    VirtQueue *tx_vq;
    QEMUTimer *tx_timer;
    QEMUBH *tx_bh;
    uint32_t tx_waiting;
    struct {
        VirtQueueElement *elem;
    } async_tx;
    struct VirtWifiInfo *n;
} VirtWifiQueue;

typedef struct VirtWifiInfo {
    VirtIODevice parent_obj;
    uint8_t mac[ETH_ALEN];
    uint16_t status;
    VirtWifiQueue *vqs;
    NICState *nic;
    virtio_wlan_conf net_conf;
    NICConf nic_conf;
    DeviceState *qdev;
    
    uint64_t host_features;

    VirtQueue *ctrl_vq;
    uint32_t tx_timeout;
    int32_t tx_burst;
    uint32_t has_vnet_hdr;
    size_t host_hdr_len;
    size_t guest_hdr_len;
    uint8_t has_ufo;
    uint32_t mergeable_rx_bufs;
    uint8_t promisc;
    uint8_t allmulti;
    uint8_t alluni;
    uint8_t nomulti;
    uint8_t nouni;
    uint8_t nobcast;
    uint8_t vhost_started;
    struct {
        uint32_t in_use;
        uint32_t first_multi;
        uint8_t multi_overflow;
        uint8_t uni_overflow;
        uint8_t *macs;
    } mac_table;
    uint32_t *vlans;
    int multiqueue;
    uint16_t max_queues;
    uint16_t curr_queues;
    size_t config_size;
    char *netclient_name;
    char *netclient_type;
    uint64_t curr_guest_offloads;
    QEMUTimer *announce_timer;
    int announce_counter;
    bool needs_vnet_hdr_swap;
    bool mtu_bypass_backend;
} VirtWifiInfo;

#endif
