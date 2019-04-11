/*
 * Virtio MAC 802.11 Device
 * NOTE: This implementation is based on virtio-net driver.
 * TODO: RX-filter, whether to filter based on nic MAC address
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/virtio/virtio.h"
#include "net/net.h"
#include "net/checksum.h"
#include "net/tap.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/virtio/virtio-mac80211.h"
#include "net/vhost_net.h"
#include "hw/virtio/virtio-bus.h"
#include "qapi/error.h"
#include "qapi/qapi-events-net.h"
#include "hw/virtio/virtio-access.h"
#include "migration/misc.h"
#include "standard-headers/linux/ethtool.h"

#define VIRTIO_ID_MAC80211              10	//virtio-ids.h

#define VIRTWIFI_MAX_QUEUE_PAIR         1
#define VIRTWIFI_DEFAULT_QUEUE		0

/* previously fixed value */
#define VWLAN_RX_QUEUE_DEFAULT_SIZE 256
#define VWLAN_TX_QUEUE_DEFAULT_SIZE 256

/* for now, only allow larger queues; with virtio-1, guest can downsize */
#define VWLAN_RX_QUEUE_MIN_SIZE VWLAN_RX_QUEUE_DEFAULT_SIZE
#define VWLAN_TX_QUEUE_MIN_SIZE VWLAN_TX_QUEUE_DEFAULT_SIZE

/*
 * Calculate the number of bytes up to and including the given 'field' of
 * 'container'.
 */
#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))

#if 0
static VirtWifiQueue *__get_subqueue(NetClientState *nc)
{
    VirtWifiInfo *n = qemu_get_nic_opaque(nc);

    return &n->vqs[VIRTWIFI_DEFAULT_QUEUE];
}
#endif

static int vq2q(int queue_index)
{
    return queue_index / 2;
}

static void __drop_tx_queue_data(VirtIODevice *vdev, VirtQueue *vq)
{
    unsigned int dropped = virtqueue_drop_all(vq);
    if (dropped) {
        virtio_notify(vdev, vq);
    }
}

static void __vwlan_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(vdev);
    struct __vwlan_config netcfg;

    virtio_stw_p(vdev, &netcfg.status, n->status);
    virtio_stw_p(vdev, &netcfg.max_virtqueue_pairs, n->max_queues);
    virtio_stw_p(vdev, &netcfg.mtu, n->net_conf.mtu);
    memcpy(netcfg.mac, n->mac, ETH_ALEN);
    //virtio_stl_p(vdev, &netcfg.speed, n->net_conf.speed);
    //netcfg.duplex = n->net_conf.duplex;
    memcpy(config, &netcfg, n->config_size);
}

static bool __vwlan_started(VirtWifiInfo *n, uint8_t status)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    return (status & VIRTIO_CONFIG_S_DRIVER_OK) &&
        (n->status & VIRTIO_MAC80211_S_LINK_UP) && vdev->vm_running;
}

static void __vwlan_set_status(struct VirtIODevice *vdev, uint8_t status)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(vdev);
    VirtWifiQueue *q;
    bool queue_started;
    uint8_t queue_status;
    
    NetClientState *ncs = qemu_get_subqueue(n->nic, 0);
    q = &n->vqs[VIRTWIFI_DEFAULT_QUEUE];

    queue_started = __vwlan_started(n, status);
    if (queue_started) {
	qemu_flush_queued_packets(ncs);
	qemu_bh_schedule(q->tx_bh);
    } else {
	qemu_bh_cancel(q->tx_bh);
	//TODO
#if 0
            if ((n->status & VIRTIO_MAC80211_S_LINK_UP) == 0 &&
                (queue_status & VIRTIO_CONFIG_S_DRIVER_OK) &&
                vdev->vm_running) {
                /* if tx is waiting we are likely have some packets in tx queue
                 * and disabled notification */
                q->tx_waiting = 0;
                virtio_queue_set_notification(q->tx_vq, 1);
                __drop_tx_queue_data(vdev, q->tx_vq);
            }
#endif
    }
}

static void __vwlan_set_link_status(NetClientState *nc)
{
    VirtWifiInfo *n = qemu_get_nic_opaque(nc);
    VirtIODevice *vdev = VIRTIO_DEVICE(n);

    uint16_t old_status = n->status;

    if (nc->link_down)
        n->status &= ~VIRTIO_MAC80211_S_LINK_UP;
    else
        n->status |= VIRTIO_MAC80211_S_LINK_UP;

    if (n->status != old_status)
        virtio_notify_config(vdev);

    __vwlan_set_status(vdev, vdev->status);
}

static void __vwlan_reset(VirtIODevice *vdev)
{
#if 0
    VirtWifiInfo *n = VIRTIO_NET(vdev);
    int i;

    /* Reset back to compatibility mode */
    n->promisc = 1;
    n->allmulti = 0;
    n->alluni = 0;
    n->nomulti = 0;
    n->nouni = 0;
    n->nobcast = 0;
    /* multiqueue is disabled by default */
    n->curr_queues = 1;
    timer_del(n->announce_timer);
    n->announce_counter = 0;
    n->status &= ~VIRTIO_NET_S_ANNOUNCE;

    /* Flush any MAC and VLAN filter table state */
    n->mac_table.in_use = 0;
    n->mac_table.first_multi = 0;
    n->mac_table.multi_overflow = 0;
    n->mac_table.uni_overflow = 0;
    memset(n->mac_table.macs, 0, MAC_TABLE_ENTRIES * ETH_ALEN);
    memcpy(&n->mac[0], &n->nic->conf->macaddr, sizeof(n->mac));
    qemu_format_nic_info_str(qemu_get_queue(n->nic), n->mac);
    memset(n->vlans, 0, MAX_VLAN >> 3);

    /* Flush any async TX */
    for (i = 0;  i < n->max_queues; i++) {
        NetClientState *nc = qemu_get_subqueue(n->nic, i);

        if (nc->peer) {
            qemu_flush_or_purge_queued_packets(nc->peer, true);
            assert(!virtio_net_get_subqueue(nc)->async_tx.elem);
        }
    }
#endif
}

static uint64_t __vwlan_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(vdev);
    NetClientState *nc = qemu_get_queue(n->nic);

    /* Firstly sync all virtio-net possible supported features */
    features |= n->host_features;

    virtio_add_feature(&features, VIRTIO_MAC80211_F_MAC);

    return features;
}

/* RX */
//mapped to guest input queue
static void __vwlan_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(vdev);
    int queue_index = vq2q(virtio_get_queue_index(vq));

    qemu_flush_queued_packets(qemu_get_subqueue(n->nic, queue_index));
}

//incoming packets from netdev
static int __vwlan_can_receive(NetClientState *nc)
{
    VirtWifiInfo *n = qemu_get_nic_opaque(nc);
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    VirtWifiQueue *q = &n->vqs[VIRTWIFI_DEFAULT_QUEUE];

    if (!vdev->vm_running) {
        return 0;
    }

    //if (nc->queue_index >= n->curr_queues) {
    //    return 0;
    //}

    if (!virtio_queue_ready(q->rx_vq) ||
        !(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return 0;
    }

    return 1;
}

static int __vwlan_has_buffers(VirtWifiQueue *q, int size)
{
    //placeholder
    VirtWifiInfo *n = q->n;

    if (virtio_queue_empty(q->rx_vq) || !virtqueue_avail_bytes(q->rx_vq, size, 0)) {
	    virtio_queue_set_notification(q->rx_vq, 1);
	    //WRT virtio-net driver, to avoid race condition following steps,
	    if (virtio_queue_empty(q->rx_vq) || !virtqueue_avail_bytes(q->rx_vq, size, 0)) {
		    return 0;
	    }
    }

    virtio_queue_set_notification(q->rx_vq, 0);
    return 1;
}

static int __vwlan_receive_filter(VirtWifiInfo *n, const uint8_t *buf, int size)
{
    //TODO: filter out packets not destined to this host
    return 1;
}

//receive callback for netdev-to-virtio-dev TODO
static ssize_t __vwlan_receive(NetClientState *nc, const uint8_t *buf,
                                  size_t size)
{
    VirtWifiInfo *n = qemu_get_nic_opaque(nc);
    VirtWifiQueue *q = &n->vqs[VIRTWIFI_DEFAULT_QUEUE];
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    struct iovec mhdr_sg[VIRTQUEUE_MAX_SIZE];
    unsigned mhdr_cnt = 0;
    size_t offset, i, guest_offset;

    virtio_error(vdev, "vwlan received len %u\n", size);

    if (!__vwlan_can_receive(nc))
	    return -1;

    if (!__vwlan_has_buffers(q, size))
	    return 0;
    if (!__vwlan_receive_filter(n, buf, size))
	    return size;

    offset = i = 0;
    while (offset < size) {
	    VirtQueueElement *elem;
	    const struct iovec *sg;
	    int len, total = 0;

	    elem = virtqueue_pop(q->rx_vq, sizeof(VirtQueueElement));
	    if (!elem) {
		    virtio_error(vdev, "virtio-mac80211 unexpected empty queue: %d", size);
		    return -1;
	    }

	    if (elem->in_num < 1) {
		    virtio_error(vdev,
                         "virtio-mac80211 receive queue contains no in buffers");
		    virtqueue_detach_element(q->rx_vq, elem, 0);
		    return -1;
	    }

	    sg = elem->in_sg;
	    len = iov_from_buf(sg, elem->in_num, 0, buf + offset, size - offset);
	    total += len;
	    offset += len;
	    if (offset < size) {
		    //XXX as no support for mergeable_rx_bufs, then why am here??
		    virtqueue_unpop(q->rx_vq, elem, total);
		    g_free(elem);
		    return size;
	    }

	    virtqueue_fill(q->rx_vq, elem, total, i++);
	    g_free(elem);
    }

    virtqueue_flush(q->rx_vq, i);
    virtio_notify(vdev, q->rx_vq);

    return size;
}

/* TX */
static int32_t __vwlan_flush_tx(VirtWifiQueue *q);

static void __vwlan_tx_complete(NetClientState *nc, ssize_t len)
{
    VirtWifiInfo *n = qemu_get_nic_opaque(nc);
    VirtWifiQueue *q = n->vqs;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);

    virtqueue_push(q->tx_vq, q->async_tx.elem, 0);
    virtio_notify(vdev, q->tx_vq);

    g_free(q->async_tx.elem);
    q->async_tx.elem = NULL;

    virtio_queue_set_notification(q->tx_vq, 1);
    __vwlan_flush_tx(q);
}

static int32_t __vwlan_flush_tx(VirtWifiQueue *q)
{
    VirtWifiInfo *n = q->n;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    VirtQueueElement *elem;
    int32_t num_packets = 0;
    int queue_index = vq2q(virtio_get_queue_index(q->tx_vq));
    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return num_packets;
    }

    if (q->async_tx.elem) {
        virtio_queue_set_notification(q->tx_vq, 0);
        return num_packets;
    }

    for (;;) {
        ssize_t ret;
        unsigned int out_num;
        struct iovec sg[VIRTQUEUE_MAX_SIZE], sg2[VIRTQUEUE_MAX_SIZE + 1], *out_sg;
        struct virtio_net_hdr_mrg_rxbuf mhdr;

        elem = virtqueue_pop(q->tx_vq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        out_num = elem->out_num;
        out_sg = elem->out_sg;
        if (out_num < 1) {
            virtio_error(vdev, "virtio-net header not in first element");
            virtqueue_detach_element(q->tx_vq, elem, 0);
            g_free(elem);
            return -EINVAL;
        }

        ret = qemu_sendv_packet_async(qemu_get_subqueue(n->nic, queue_index),
                                      out_sg, out_num, __vwlan_tx_complete);
        if (ret == 0) {
            virtio_queue_set_notification(q->tx_vq, 0);
            q->async_tx.elem = elem;
            return -EBUSY;
        }

drop:
        virtqueue_push(q->tx_vq, elem, 0);
        virtio_notify(vdev, q->tx_vq);
        g_free(elem);

        if (++num_packets >= n->tx_burst) {
            break;
        }
    }
    return num_packets;
}

static void __vwlan_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(vdev);
    VirtWifiQueue *q = &n->vqs[vq2q(virtio_get_queue_index(vq))];

    if (unlikely((n->status & VIRTIO_MAC80211_S_LINK_UP) == 0)) {
        __drop_tx_queue_data(vdev, vq);
        return;
    }

    if (unlikely(q->tx_waiting)) {
        return;
    }
    q->tx_waiting = 1;
    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running) {
        return;
    }
    virtio_queue_set_notification(vq, 0);
    qemu_bh_schedule(q->tx_bh);
}

static void __vwlan_tx_bh(void *opaque)
{
    VirtWifiQueue *q = opaque;
    VirtWifiInfo *n = q->n;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    int32_t ret;

    /* This happens when device was stopped but BH wasn't. */
    if (!vdev->vm_running) {
        /* Make sure tx waiting is set, so we'll run when restarted. */
        assert(q->tx_waiting);
        return;
    }

    q->tx_waiting = 0;

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
        return;
    }

    ret = __vwlan_flush_tx(q);
    if (ret == -EBUSY || ret == -EINVAL) {
        return; /* Notification re-enable handled by tx_complete or device
                 * broken */
    }

    /* If we flush a full burst of packets, assume there are
     * more coming and immediately reschedule */
    if (ret >= n->tx_burst) {
        qemu_bh_schedule(q->tx_bh);
        q->tx_waiting = 1;
        return;
    }

    /* If less than a full burst, re-enable notification and flush
     * anything that may have come in while we weren't looking.  If
     * we find something, assume the guest is still active and reschedule */
    virtio_queue_set_notification(q->tx_vq, 1);
    ret = __vwlan_flush_tx(q);
    if (ret == -EINVAL) {
        return;
    } else if (ret > 0) {
        virtio_queue_set_notification(q->tx_vq, 0);
        qemu_bh_schedule(q->tx_bh);
        q->tx_waiting = 1;
    }
}

#if 0	//TODO for _unrealize
static void virtio_net_del_queue(VirtWifiInfo *n, int index)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    VirtWifiQueue *q = &n->vqs[index];
    NetClientState *nc = qemu_get_subqueue(n->nic, index);

    qemu_purge_queued_packets(nc);

    virtio_del_queue(vdev, index * 2);
    if (q->tx_timer) {
        timer_del(q->tx_timer);
        timer_free(q->tx_timer);
        q->tx_timer = NULL;
    } else {
        qemu_bh_delete(q->tx_bh);
        q->tx_bh = NULL;
    }
    q->tx_waiting = 0;
    virtio_del_queue(vdev, index * 2 + 1);
}
#endif

static NetClientInfo __vwlan_client_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = __vwlan_can_receive,
    .receive = __vwlan_receive,
    .link_status_changed = __vwlan_set_link_status,
};

static void __set_config_size(VirtWifiInfo *n, uint64_t host_features)
{
    int i, config_size = 0;
    virtio_add_feature(&host_features, VIRTIO_MAC80211_F_MAC);

    //n->config_size = endof(struct virtio_net_config, mac);
    n->config_size = sizeof(struct __vwlan_config);
}

static void __vwlan_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(dev);
    NetClientState *nc;
    int i;

    n->net_conf.mtu = 1500;
    n->host_features |= (1ULL << VIRTIO_NET_F_MTU);
    n->net_conf.duplex = DUPLEX_FULL;
    n->host_features |= (1ULL << VIRTIO_NET_F_SPEED_DUPLEX);
    n->net_conf.rx_queue_size = VWLAN_RX_QUEUE_MIN_SIZE;
    n->net_conf.tx_queue_size = VWLAN_TX_QUEUE_MIN_SIZE;

    __set_config_size(n, n->host_features);	//TODO
    virtio_init(vdev, "virtio-mac80211", VIRTIO_ID_MAC80211, n->config_size);

    n->max_queues = VIRTWIFI_MAX_QUEUE_PAIR;
    n->vqs = g_malloc0(sizeof(VirtWifiQueue) * n->max_queues);
    n->curr_queues = 1;
    n->tx_timeout = n->net_conf.txtimer;

    n->vqs[VIRTWIFI_DEFAULT_QUEUE].rx_vq = virtio_add_queue(vdev, n->net_conf.rx_queue_size,
    					__vwlan_handle_rx);

    n->vqs[VIRTWIFI_DEFAULT_QUEUE].tx_vq = virtio_add_queue(vdev, n->net_conf.tx_queue_size,
    					__vwlan_handle_tx);
    n->vqs[VIRTWIFI_DEFAULT_QUEUE].tx_bh = qemu_bh_new(__vwlan_tx_bh, &n->vqs[VIRTWIFI_DEFAULT_QUEUE]);
    n->vqs[VIRTWIFI_DEFAULT_QUEUE].tx_waiting = 0;
    n->vqs[VIRTWIFI_DEFAULT_QUEUE].n = n;

#if 0	//no control queue
    n->ctrl_vq = virtio_add_queue(vdev, 64, virtio_net_handle_ctrl);
#endif

    qemu_macaddr_default_if_unset(&n->nic_conf.macaddr);
    memcpy(&n->mac[0], &n->nic_conf.macaddr, sizeof(n->mac));
    n->status = VIRTIO_MAC80211_S_LINK_UP;
    //n->announce_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
    //                                 virtio_net_announce_timer, n);

    n->nic = qemu_new_nic(&__vwlan_client_info, &n->nic_conf,
                              object_get_typename(OBJECT(dev)), dev->id, n);

    n->host_hdr_len = 0;

    qemu_format_nic_info_str(qemu_get_queue(n->nic), n->nic_conf.macaddr.a);

    n->vqs[VIRTWIFI_DEFAULT_QUEUE].tx_waiting = 0;
    n->tx_burst = n->net_conf.txburst;
    n->promisc = 1;

    n->qdev = dev;
    //TODO check if [virtio_notify_config(vdev);] needs to be added here
}

static void __vwlan_device_unrealize(DeviceState *dev, Error **errp)
{
#if 0
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtWifiInfo *n = VIRTIO_NET(dev);
    int i, max_queues;

    /* This will stop vhost backend if appropriate. */
    virtio_net_set_status(vdev, 0);

    g_free(n->netclient_name);
    n->netclient_name = NULL;
    g_free(n->netclient_type);
    n->netclient_type = NULL;

    g_free(n->mac_table.macs);
    g_free(n->vlans);

    max_queues = n->multiqueue ? n->max_queues : 1;
    for (i = 0; i < max_queues; i++) {
        virtio_net_del_queue(n, i);
    }

    timer_del(n->announce_timer);
    timer_free(n->announce_timer);
    g_free(n->vqs);
    qemu_del_nic(n->nic);
    virtio_cleanup(vdev);
#endif
}

static void __vwlan_instance_init(Object *obj)
{
    VirtWifiInfo *n = VIRTIO_MAC80211_OBJ(obj);

    n->config_size = sizeof(struct __vwlan_config);
}

//TODO
static int __vwlan_post_load(void *opaque, int version_id)
{
    VirtWifiInfo *n = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(n);
    int link_down;

    link_down = (n->status & VIRTIO_MAC80211_S_LINK_UP) == 0;
    qemu_get_subqueue(n->nic, VIRTWIFI_DEFAULT_QUEUE)->link_down = link_down;

    return 0;
}

//TODO
static int __vwlan_pre_save(void *opaque)
{
    VirtWifiInfo *n = opaque;

    //assert(!n->vhost_started);

    return 0;
}

static const VMStateDescription vwlan_vmstate = {
    .name = "virtio-mac80211",
    .minimum_version_id = 1,
    .version_id = 1,
    .pre_load	= NULL,
    .post_load 	= __vwlan_post_load,
    .pre_save = __vwlan_pre_save,
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property vwlan_properties[] = {
    DEFINE_PROP_BIT64("status", VirtWifiInfo, host_features,
                    VIRTIO_MAC80211_F_STATUS, true),
    DEFINE_NIC_PROPERTIES(VirtWifiInfo, nic_conf),	/*NICCONF*/
    DEFINE_PROP_STRING("tx", VirtWifiInfo, net_conf.tx),
    DEFINE_PROP_UINT16("rx_queue_size", VirtWifiInfo, net_conf.rx_queue_size,
                       VWLAN_RX_QUEUE_DEFAULT_SIZE),
    DEFINE_PROP_UINT16("tx_queue_size", VirtWifiInfo, net_conf.tx_queue_size,
                       VWLAN_TX_QUEUE_DEFAULT_SIZE),
    DEFINE_PROP_UINT16("host_mtu", VirtWifiInfo, net_conf.mtu, 0),
    DEFINE_PROP_INT32("speed", VirtWifiInfo, net_conf.speed, SPEED_UNKNOWN),
    DEFINE_PROP_STRING("duplex", VirtWifiInfo, net_conf.duplex_str),
    DEFINE_PROP_END_OF_LIST(),
};

static void __vwlan_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props 	= vwlan_properties;
    dc->vmsd 	= &vwlan_vmstate;
    dc->desc 	= "Virtio MAC 802.11 controller";
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);

    vdc->realize 	= __vwlan_device_realize;
    vdc->unrealize 	= __vwlan_device_unrealize;
    vdc->get_config 	= __vwlan_get_config;
    //vdc->set_config 	= __vwlan_set_config;
    vdc->get_features 	= __vwlan_get_features;
    vdc->set_status 	= __vwlan_set_status;
    vdc->reset 		= __vwlan_reset;
}

static const TypeInfo vwlan_info = {
    .name = TYPE_VIRTIO_MAC80211,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtWifiInfo),
    .instance_init = __vwlan_instance_init,
    .class_init = __vwlan_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&vwlan_info);
}

type_init(virtio_register_types)
