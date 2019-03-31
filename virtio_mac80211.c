/*
 * A modified mac80211_hwsim, to work as virtio frontend driver
 * in short, virtio_mac80211 = mac80211_hwsim + virtio_net
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * function naming: <virtwifi> virtio specific & <vwlan> mac80211 specific
 * TODO: Please refer to mac80211_hwsim TODO list
 * 1. Per link signal-to-noise ratio model to be added in qemu backend driver, 
 *      frontend driver to be updated accordingly (reference wmediumd)
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <net/route.h>

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/mac80211.h>
#include <net/ieee80211_radiotap.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/platform_device.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "virtio_mac80211.h"

//#define MAC80211_RTAP_SUPPORT		/* TODO radiotap monitor dev support */
#define DEBUG_ALL			/* debug enable */

#define VIRTIO_ID_MAC80211		10 /* virtio mac802.11 */
#define VIRTWIFI_RADIOS_MAX		1  /* max radios per vwlan */
#define VIRTWIFI_CHANNELS_MAX		1  /* max channels per radios */
#define VIRTWIFI_MAX_QUEUE_PAIR		1 /* single rx-tx queue for now */


#define WARN_QUEUE 100
#define MAX_QUEUE 200
#define DEFAULT_VIRTQUEUE	0

//TODO: make all module params as virtio config
//only one radio per virtio-wlan device
#if 0
static int radios = 1;
module_param(radios, int, 0444);
MODULE_PARM_DESC(radios, "Number of simulated radios");

static int channels = 1;
module_param(channels, int, 0444);
MODULE_PARM_DESC(channels, "Number of concurrent channels");
#endif

static bool paged_rx = false;
module_param(paged_rx, bool, 0644);
MODULE_PARM_DESC(paged_rx, "Use paged SKBs for RX instead of linear ones");

static bool rctbl = false;
module_param(rctbl, bool, 0444);
MODULE_PARM_DESC(rctbl, "Handle rate control table");

static bool support_p2p_device = false;
module_param(support_p2p_device, bool, 0444);
MODULE_PARM_DESC(support_p2p_device, "Support P2P-Device interface type");

#define VIRTNET_DRIVER_VERSION "1.0.0"

#define CHAN2G(_freq)  { \
        .band = NL80211_BAND_2GHZ, \
        .center_freq = (_freq), \
        .hw_value = (_freq), \
        .max_power = 20, \
}

#define CHAN5G(_freq) { \
        .band = NL80211_BAND_5GHZ, \
        .center_freq = (_freq), \
        .hw_value = (_freq), \
        .max_power = 20, \
}

static const struct ieee80211_channel vwlan_channels_2ghz[] = {
        CHAN2G(2412), /* Channel 1 */
        CHAN2G(2417), /* Channel 2 */
        CHAN2G(2422), /* Channel 3 */
        CHAN2G(2427), /* Channel 4 */
        CHAN2G(2432), /* Channel 5 */
        CHAN2G(2437), /* Channel 6 */
        CHAN2G(2442), /* Channel 7 */
        CHAN2G(2447), /* Channel 8 */
        CHAN2G(2452), /* Channel 9 */
        CHAN2G(2457), /* Channel 10 */
        CHAN2G(2462), /* Channel 11 */
        CHAN2G(2467), /* Channel 12 */
        CHAN2G(2472), /* Channel 13 */
        CHAN2G(2484), /* Channel 14 */
};

static const struct ieee80211_channel vwlan_channels_5ghz[] = {
        CHAN5G(5180), /* Channel 36 */
        CHAN5G(5200), /* Channel 40 */
        CHAN5G(5220), /* Channel 44 */
        CHAN5G(5240), /* Channel 48 */

        CHAN5G(5260), /* Channel 52 */
        CHAN5G(5280), /* Channel 56 */
        CHAN5G(5300), /* Channel 60 */
        CHAN5G(5320), /* Channel 64 */

        CHAN5G(5500), /* Channel 100 */
        CHAN5G(5520), /* Channel 104 */
        CHAN5G(5540), /* Channel 108 */
        CHAN5G(5560), /* Channel 112 */
        CHAN5G(5580), /* Channel 116 */
        CHAN5G(5600), /* Channel 120 */
        CHAN5G(5620), /* Channel 124 */
        CHAN5G(5640), /* Channel 128 */
        CHAN5G(5660), /* Channel 132 */
        CHAN5G(5680), /* Channel 136 */
        CHAN5G(5700), /* Channel 140 */

        CHAN5G(5745), /* Channel 149 */
        CHAN5G(5765), /* Channel 153 */
        CHAN5G(5785), /* Channel 157 */
        CHAN5G(5805), /* Channel 161 */
        CHAN5G(5825), /* Channel 165 */
        CHAN5G(5845), /* Channel 169 */
};

static const struct ieee80211_rate vwlan_rates[] = {
        { .bitrate = 10 },
        { .bitrate = 20, .flags = IEEE80211_RATE_SHORT_PREAMBLE },
        { .bitrate = 55, .flags = IEEE80211_RATE_SHORT_PREAMBLE },
        { .bitrate = 110, .flags = IEEE80211_RATE_SHORT_PREAMBLE },
        { .bitrate = 60 },
        { .bitrate = 90 },
        { .bitrate = 120 },
        { .bitrate = 180 },
        { .bitrate = 240 },
        { .bitrate = 360 },
        { .bitrate = 480 },
        { .bitrate = 540 }
};

struct vwlan_chanctx_priv {
        u32 magic;
};

struct vwlan_priv_data;

#define HWSIM_CHANCTX_MAGIC 0x6d53774a

struct vwlan_vif_priv {
        u32 magic;
        u8 bssid[ETH_ALEN];
        bool assoc;
        bool bcn_en;
        u16 aid;

	struct vwlan_priv_data *priv;

	/* beaconing */
        struct delayed_work beacon_work;
        bool enable_beacon;
};

#define HWSIM_VIF_MAGIC 0x69537748

struct vwlan_sta_priv {
        u32 magic;
};

#define HWSIM_STA_MAGIC 0x6d537749

/* Internal representation of a send virtqueue 
 * @vq: Virtqueue associated with this send _queue
 * @sg: TX: fragments + linear part + virtio header
 * @name: Name of the send queue: output.$index
 */
struct send_queue {
        struct virtqueue *vq;
        struct scatterlist sg[MAX_SKB_FRAGS + 2];
        char name[40];
        //struct napi_struct napi;	//TODO unused
};

/* Internal representation of a receive virtqueue 
 * @vq: Virtqueue associated with this receive_queue
 * @pages: Chain pages by the private ptr.
 * @ewma_pkt_len: Average packet length for mergeable receive buffers.
 * @alloc_frag: Page frag for packet buffer allocation.
 * @sg: RX: fragments + linear part + virtio header
 * @min_buf_len: Min single buffer size for mergeable buffers case.
 * @name: Name of this receive queue: input.$index
 */
struct receive_queue {
        struct virtqueue *vq;
        //struct napi_struct napi;	//unused
        //struct bpf_prog __rcu *xdp_prog;	//xdp unused
        struct page *pages;
        //struct ewma_pkt_len mrg_avg_pkt_len;
        struct page_frag alloc_frag;
        struct scatterlist sg[MAX_SKB_FRAGS + 2];
        unsigned int min_buf_len;
        char name[40];
};

//mac80211_hwsim_data
struct vwlan_priv_data {
	struct ieee80211_hw *hw;
	struct device *dev;
	struct ieee80211_supported_band bands[NUM_NL80211_BANDS];
	struct ieee80211_channel channels_2ghz[ARRAY_SIZE(vwlan_channels_2ghz)];
	struct ieee80211_channel channels_5ghz[ARRAY_SIZE(vwlan_channels_5ghz)];
	struct ieee80211_rate rates[ARRAY_SIZE(vwlan_rates)];
	struct ieee80211_iface_combination if_combination;

	struct mac_address addresses[2];
	int channels, idx;
	bool use_chanctx;
	bool destroy_on_close;
	struct work_struct destroy_work;
	u32 portid;
	char alpha2[2];
	const struct ieee80211_regdomain *regd;

#if 0
	struct ieee80211_channel *tmp_chan;
	struct ieee80211_channel *roc_chan;
	u32 roc_duration;
	struct delayed_work roc_start;
	struct delayed_work roc_done;
	struct delayed_work hw_scan;
#endif
	struct cfg80211_scan_request *hw_scan_request;
	struct ieee80211_vif *hw_scan_vif;
	int scan_chan_idx;
	u8 scan_addr[ETH_ALEN];
	struct {
		struct ieee80211_channel *channel;
		unsigned long next_start, start, end;
	} survey_data[ARRAY_SIZE(vwlan_channels_2ghz) +
	ARRAY_SIZE(vwlan_channels_5ghz)];

	struct ieee80211_channel *channel;

	u64 beacon_int  /* beacon interval in us */;
	unsigned int rx_filter;
	bool started, idle, scanning;
	struct mutex mutex;
	struct tasklet_hrtimer beacon_timer;
	enum ps_mode {
		PS_DISABLED, PS_ENABLED, PS_AUTO_POLL, PS_MANUAL_POLL
	} ps;
	bool ps_poll_pending;
	struct dentry *debugfs;

	uintptr_t pending_cookie;
	struct sk_buff_head pending;    /* packets pending */
	/*
	 * Only radios in the same group can communicate together (the
	 * channel has to match too). Each bit represents a group. A
	 * radio can be in more than one group.
	 */
	u64 group;

	/* group shared by radios created in the same netns */
	int netgroup;
	/* wmediumd portid responsible for netgroup of this radio */
	u32 wmediumd;

	/* difference between this hw's clock and the real clock, in usecs */
	s64 tsf_offset;
	s64 bcn_delta;
	/* absolute beacon transmission time. Used to cover up "tx" delay. */
	u64 abs_bcn_ts;

};

/*
 * virtwifi_info: virtio specific MAC802.11 (TODO: cleanup unused)
 * @max_queue_pairs: Max # of queue pairs supported by the device
 * @curr_queue_pairs: # of queue pairs currently used by the driver
 * @xdp_queue_pairs: # of XDP queue pairs currently used by the driver
 * @big_packets
 * @mergeable_rx_bufs: Host will merge rx buffers for big packets
 * @has_cvq: Has control virtqueue
 * @any_header_sg: Host can handle any s/g split between our header and packet data
 * @hdr_len: Packet virtio header size
 * @refill: Work struct for refilling if we run low on memory.
 * @config_work: Work struct for config space updates
 * @affinity_hint_set: Does the affinity hint is set for virtqueues?
 * @node/node_dead: CPU hotplug instances for online & dead
 * @duplex/speed: Ethtool settings
 */
struct virtwifi_info {
	struct list_head list;	//vwlan list
	struct vwlan_priv_data priv;

	struct {	//virtio specific
		struct virtio_device *vdev;
		struct virtqueue *cvq;
		struct send_queue *sq;
		struct receive_queue *rq;

		u16 max_queue_pairs;
		u16 curr_queue_pairs;
		u16 xdp_queue_pairs;

		bool big_packets;
		bool mergeable_rx_bufs;
		bool has_cvq;
		bool any_header_sg;
		u8 hdr_len;
		struct delayed_work refill;
		struct work_struct config_work;
		bool affinity_hint_set;

		struct control_buf *ctrl;

		unsigned long guest_offloads;
	};

	//TODO: CPU hot-plug related, to cleanup
	struct hlist_node node;
	struct hlist_node node_dead;

	struct {
		/* Stats */
		u64 tx_pkts;
		u64 rx_pkts;
		u64 tx_bytes;
		u64 rx_bytes;
		u64 tx_dropped;
		u64 rx_dropped;
		u64 tx_failed;
	};
	u8 duplex;	//for ethtool
	u32 speed;
	unsigned int status;
};

//TODO: mesh_point | ADHOC | p2p_client
static const struct ieee80211_iface_limit vwlan_mac80211_limits[] = {
        { .max = 1, .types = BIT(NL80211_IFTYPE_STATION), },
        { .max = 1, .types = BIT(NL80211_IFTYPE_AP), },
};

static const struct ieee80211_iface_combination vwlan_mac80211_comb[] = {
        {
                .limits = vwlan_mac80211_limits,
                .n_limits = ARRAY_SIZE(vwlan_mac80211_limits),
                .max_interfaces = 2,
                .num_different_channels = 1,
		/* .beacon_int_infra_match = true, */
                .radar_detect_widths = BIT(NL80211_CHAN_WIDTH_20_NOHT) |
                                       BIT(NL80211_CHAN_WIDTH_20) |
                                       BIT(NL80211_CHAN_WIDTH_40) |
                                       BIT(NL80211_CHAN_WIDTH_80) |
                                       BIT(NL80211_CHAN_WIDTH_160),
        },
};

/* global */
static spinlock_t vwlan_radio_lock;
static int vwlan_radio_idx = 0;
static LIST_HEAD(vwlan_radios);

#define VWLAN_NAME	"vwlan%d"

#ifdef MAC80211_RTAP_SUPPORT
//radiotap monitoring interface support (ref. mac80211_hwsim) */
static struct net_device *hwsim_mon;
#endif //MAC80211_RTAP_SUPPORT

//------------------ieee80211_ops impl-----------------------

#if 0
static void __vwlan_roc_start(struct work_struct *work)
{
	struct vwlan_priv_data *data =
		container_of(work, struct vwlan_priv_data, roc_start.work);

        mutex_lock(&data->mutex);

        wiphy_dbg(data->hw->wiphy, "ROC begins\n");
        data->tmp_chan = data->roc_chan;
        ieee80211_ready_on_channel(data->hw);

        ieee80211_queue_delayed_work(data->hw, &data->roc_done,
                                     msecs_to_jiffies(data->roc_duration));

        mutex_unlock(&data->mutex);
}

static void __vwlan_roc_done(struct work_struct *work)
{
	struct vwlan_priv_data *data =
		container_of(work, struct vwlan_priv_data, roc_done.work);

        mutex_lock(&data->mutex);
        ieee80211_remain_on_channel_expired(data->hw);
        data->tmp_chan = NULL;
        mutex_unlock(&data->mutex);

        wiphy_dbg(data->hw->wiphy, "ROC expired\n");
}

static void __vwlan_scan_work(struct work_struct *work)
{
	struct vwlan_priv_data *data =
		container_of(work, struct vwlan_priv_data, hw_scan.work);
	struct cfg80211_scan_request *req = data->hw_scan_request;
	int dwell, i;

	mutex_lock(&data->mutex);
	if (data->scan_chan_idx >= req->n_channels) {
		struct cfg80211_scan_info info = {
			.aborted = false,
		};

		wiphy_dbg(hwsim->hw->wiphy, "scan complete\n");
		ieee80211_scan_completed(data->hw, &info);
		data->hw_scan_request = NULL;
		data->hw_scan_vif = NULL;
		data->tmp_chan = NULL;
		mutex_unlock(&data->mutex);
		return;
	}

	wiphy_dbg(data->hw->wiphy, "hw scan %d MHz\n",
			req->channels[data->scan_chan_idx]->center_freq);

	data->tmp_chan = req->channels[data->scan_chan_idx];
	if (data->tmp_chan->flags & (IEEE80211_CHAN_NO_IR |
				IEEE80211_CHAN_RADAR) ||
			!req->n_ssids) {
		dwell = 120;
	} else {
		dwell = 30;
		/* send probes */
		for (i = 0; i < req->n_ssids; i++) {
			struct sk_buff *probe;
			struct ieee80211_mgmt *mgmt;

			probe = ieee80211_probereq_get(data->hw,
					data->scan_addr,
					req->ssids[i].ssid,
					req->ssids[i].ssid_len,
					req->ie_len);
			if (!probe)
				continue;

			mgmt = (struct ieee80211_mgmt *) probe->data;
			memcpy(mgmt->da, req->bssid, ETH_ALEN);
			memcpy(mgmt->bssid, req->bssid, ETH_ALEN);
			if (req->ie_len)
				skb_put_data(probe, req->ie, req->ie_len);

			local_bh_disable();
			mac80211_hwsim_tx_frame(data->hw, probe,
					data->tmp_chan);		//TODO
			local_bh_enable();
		}
	}
	ieee80211_queue_delayed_work(data->hw, &data->hw_scan,
			msecs_to_jiffies(dwell));
	data->survey_data[data->scan_chan_idx].channel = data->tmp_chan;
	data->survey_data[data->scan_chan_idx].start = jiffies;
	data->survey_data[data->scan_chan_idx].end =
		jiffies + msecs_to_jiffies(dwell);
	data->scan_chan_idx++;
	mutex_unlock(&data->mutex);
}
#endif

static void __vwlan_mac80211_tx_internal(struct virtwifi_info *info,
					struct ieee80211_tx_control *control,
					struct send_queue *sq,
					struct sk_buff *skb)
{
	int num_sg;
	int err;

	pr_info("__vwlan_mac80211_tx_internal: onward to virtqueue!!\n");

	sg_init_table(sq->sg, (skb_shinfo(skb)->nr_frags + 1));
	sg_set_buf(sq->sg, skb->data, skb_headlen(skb));
	num_sg = skb_to_sgvec(skb, sq->sg + 1, 0, skb->len);
	if (unlikely(num_sg < 0))
		return;
	num_sg++;
	//add it to send queue, virtqueue_kick()
	err = virtqueue_add_outbuf(sq->vq, sq->sg, num_sg, skb, GFP_ATOMIC);
	if (unlikely(err)) {
		pr_err("%s Unexpected TX queue failure: %d\n", __func__, err);
		info->tx_dropped++;
		dev_kfree_skb_any(skb);
		return;
	}

	pr_info("%s: kick send queue!!\n", __func__);
	//TODO check if running out of space, stop queue if needed
	virtqueue_kick(sq->vq);
}

static void __free_old_xmit_skbs(struct virtwifi_info *, struct send_queue *);

//TODO
static void __vwlan_mac80211_tx(struct ieee80211_hw *hw,
                              struct ieee80211_tx_control *control,
                              struct sk_buff *skb)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);
	struct send_queue *sq = &(info->sq[DEFAULT_VIRTQUEUE]);

	struct ieee80211_tx_info *txi = IEEE80211_SKB_CB(skb);
	//struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) skb->data;
	//struct ieee80211_chanctx_conf *chanctx_conf;
	struct ieee80211_channel *channel = NULL;
	//bool ack;

	if (WARN_ON(skb->len < 10)) {
		/* Should not happen; just a sanity check for addr1 use */
		ieee80211_free_txskb(hw, skb);
		return;
	}

	__free_old_xmit_skbs(info, sq);	//TODO clear used skbs

	//if (!skb->xmit_more)	//TODO: is it needed for wifi packet?
		virtqueue_enable_cb_delayed(sq->vq);

	if (!data->use_chanctx)	//currently no support for use_chanctx
		channel = data->channel;

	if (WARN(!channel, "TX w/o channel - queue = %d\n", txi->hw_queue)) {
		ieee80211_free_txskb(hw, skb);
		return;
	}

	if (data->idle /*&& !data->tmp_chan*/) {
		wiphy_dbg(hw->wiphy, "Trying to TX when idle - reject\n");
		ieee80211_free_txskb(hw, skb);
		return;
	}

	if (txi->control.vif)
		pr_info("TODO vif\n");

	if (control && control->sta)
		pr_info("TODO sta\n");

	if (ieee80211_hw_check(hw, SUPPORTS_RC_TABLE))
		ieee80211_get_tx_rates(txi->control.vif, control->sta, skb,
				txi->control.rates,
				ARRAY_SIZE(txi->control.rates));

	//skb_tx_timestamp(skb);

	//TODO check is_probe_resp()
#ifdef MAC80211_RTAP_SUPPORT
	//call monitor_rx()
#endif
	//TODO tx stat update here or at free_tx_skbs()

	__vwlan_mac80211_tx_internal(info, control, sq, skb);

	ieee80211_tx_info_clear_status(txi);

	/* frame was transmitted at most favorable rate at first attempt */
	txi->control.rates[0].count = 1;
	txi->control.rates[1].idx = -1;

	if (!(txi->flags & IEEE80211_TX_CTL_NO_ACK)/* && ack*/)
		txi->flags |= IEEE80211_TX_STAT_ACK;

	ieee80211_tx_status_irqsafe(hw, skb);
}

static int __vwlan_mac80211_start(struct ieee80211_hw *hw)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct send_queue *sq = &info->sq[DEFAULT_VIRTQUEUE];
	struct receive_queue *rq = &info->rq[DEFAULT_VIRTQUEUE];

	wiphy_dbg(hw->wiphy, "%s\n", __func__);

	//TODO may be add MAC here

	//normally register rx/tx intr here
	if (!virtqueue_enable_cb_delayed(sq->vq))
		return -EINVAL;

	if (!virtqueue_enable_cb_delayed(rq->vq))
		goto err_disable_sq;

	info->priv.started = true;
	pr_info("%s: vwlan started\n", __func__);

	return 0;

err_disable_sq:
	virtqueue_disable_cb(sq->vq);
	return -EINVAL;
}

static void __vwlan_mac80211_stop(struct ieee80211_hw *hw)
{
        struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct send_queue *sq = &info->sq[DEFAULT_VIRTQUEUE];
	struct receive_queue *rq = &info->rq[DEFAULT_VIRTQUEUE];

        info->priv.started = false;
	virtqueue_disable_cb(sq->vq);
	virtqueue_disable_cb(rq->vq);
        wiphy_dbg(hw->wiphy, "%s\n", __func__);
}

static void __vwlan_beacon_work(struct work_struct *);

static int __vwlan_mac80211_add_interface(struct ieee80211_hw *hw,
                                        struct ieee80211_vif *vif)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_vif_priv *vif_priv;

        wiphy_dbg(hw->wiphy, "%s (type=%d mac_addr=%pM)\n",
                  __func__, ieee80211_vif_type_p2p(vif),
                  vif->addr);
        //hwsim_set_magic(vif);

        vif->cab_queue = 0;
        vif->hw_queue[IEEE80211_AC_VO] = 0;
        vif->hw_queue[IEEE80211_AC_VI] = 1;
        vif->hw_queue[IEEE80211_AC_BE] = 2;
        vif->hw_queue[IEEE80211_AC_BK] = 3;

	vif_priv = (struct vwlan_vif_priv *) vif->drv_priv;
	vif_priv->priv = &(info->priv);

	INIT_DELAYED_WORK(&vif_priv->beacon_work, __vwlan_beacon_work);
	vif_priv->enable_beacon = false;

	//TODO try_fill_recv()

	pr_info("%s (type=%d mac_addr=%pM)\n", __func__, 
		ieee80211_vif_type_p2p(vif), vif->addr);

        return 0;
}

static int __vwlan_mac80211_change_interface(struct ieee80211_hw *hw,
                                           struct ieee80211_vif *vif,
                                           enum nl80211_iftype newtype,
                                           bool newp2p)
{
#if 0
        newtype = ieee80211_iftype_p2p(newtype, newp2p);
        wiphy_dbg(hw->wiphy,
                  "%s (old type=%d, new type=%d, mac_addr=%pM)\n",
                  __func__, ieee80211_vif_type_p2p(vif),
                    newtype, vif->addr);
        //hwsim_check_magic(vif);
#endif
	pr_info("%s mac_addr=%pM\n", __func__, vif->addr);

        /*
         * interface may change from non-AP to AP in
         * which case this needs to be set up again
         */
        vif->cab_queue = 0;

        return 0;
}

static void __vwlan_mac80211_remove_interface(struct ieee80211_hw *hw, 
					struct ieee80211_vif *vif)
{
	struct vwlan_vif_priv *vif_priv = (struct vwlan_vif_priv *) vif->drv_priv;

        wiphy_dbg(hw->wiphy, "%s (type=%d mac_addr=%pM)\n",
                  __func__, ieee80211_vif_type_p2p(vif),
                  vif->addr);
        //hwsim_check_magic(vif);
        //hwsim_clear_magic(vif);
	vif_priv->priv->started = false;

	pr_info("%s (type=%d mac_addr=%pM)\n", __func__, 
		ieee80211_vif_type_p2p(vif), vif->addr);
}

static const char * const vwlan_chanwidths[] = {
        [NL80211_CHAN_WIDTH_20_NOHT] = "noht",
        [NL80211_CHAN_WIDTH_20] = "ht20",
        [NL80211_CHAN_WIDTH_40] = "ht40",
        [NL80211_CHAN_WIDTH_80] = "vht80",
        [NL80211_CHAN_WIDTH_80P80] = "vht80p80",
        [NL80211_CHAN_WIDTH_160] = "vht160",
};

static int __vwlan_mac80211_config(struct ieee80211_hw *hw, u32 changed)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);
	struct ieee80211_conf *conf = &(hw->conf);

	static const char *smps_modes[IEEE80211_SMPS_NUM_MODES] = {
		[IEEE80211_SMPS_AUTOMATIC] = "auto",
		[IEEE80211_SMPS_OFF] = "off",
		[IEEE80211_SMPS_STATIC] = "static",
		[IEEE80211_SMPS_DYNAMIC] = "dynamic",
	};
	int idx;

	if (conf->chandef.chan)
		wiphy_dbg(hw->wiphy,
				"%s (freq=%d(%d - %d)/%s idle=%d ps=%d smps=%s)\n",
				__func__,
				conf->chandef.chan->center_freq,
				conf->chandef.center_freq1,
				conf->chandef.center_freq2,
				vwlan_chanwidths[conf->chandef.width],
				!!(conf->flags & IEEE80211_CONF_IDLE),
				!!(conf->flags & IEEE80211_CONF_PS),
				smps_modes[conf->smps_mode]);
	else
		wiphy_dbg(hw->wiphy,
				"%s (freq=0 idle=%d ps=%d smps=%s)\n",
				__func__,
				!!(conf->flags & IEEE80211_CONF_IDLE),
				!!(conf->flags & IEEE80211_CONF_PS),
				smps_modes[conf->smps_mode]);

	data->idle = !!(conf->flags & IEEE80211_CONF_IDLE);

	mutex_lock(&data->mutex);
	if (data->scanning && conf->chandef.chan) {
		/* only valid as .sw_scan_start/complete APIs 
		 * are implemented 
		 */
		for (idx = 0; idx < ARRAY_SIZE(data->survey_data); idx++) {
			if (data->survey_data[idx].channel == data->channel) {
				data->survey_data[idx].start =
					data->survey_data[idx].next_start;
				data->survey_data[idx].end = jiffies;
				break;
			}
		}

		data->channel = conf->chandef.chan;

		for (idx = 0; idx < ARRAY_SIZE(data->survey_data); idx++) {
			if (data->survey_data[idx].channel &&
				data->survey_data[idx].channel != data->channel)
				continue;
			data->survey_data[idx].channel = data->channel;
			data->survey_data[idx].next_start = jiffies;
			break;
		}
	} else {
		data->channel = conf->chandef.chan;
	}
	mutex_unlock(&data->mutex);

	return 0;
}

static void __vwlan_mac80211_configure_filter(struct ieee80211_hw *hw,
					    unsigned int changed_flags,
					    unsigned int *total_flags,u64 multicast)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);

	wiphy_dbg(hw->wiphy, "%s\n", __func__);

	data->rx_filter = 0;
	if (*total_flags & FIF_ALLMULTI)
		data->rx_filter |= FIF_ALLMULTI;

	*total_flags = data->rx_filter;
	pr_info("%s XXXX not sure what to configure\n", __func__);
}

static void __vwlan_mac80211_bss_info_changed(struct ieee80211_hw *hw,
					    struct ieee80211_vif *vif,
					    struct ieee80211_bss_conf *info,
					    u32 changed)
{
	struct vwlan_vif_priv *vif_priv = (struct vwlan_vif_priv *) vif->drv_priv;
	struct vwlan_priv_data *data = vif_priv->priv;

	//hwsim_check_magic(vif);

	wiphy_dbg(hw->wiphy, "%s(changed=0x%x vif->addr=%pM)\n",
		  __func__, changed, vif->addr);

	if (changed & BSS_CHANGED_BSSID) {
		wiphy_dbg(hw->wiphy, "%s: BSSID changed: %pM\n",
			  __func__, info->bssid);
		memcpy(vif_priv->bssid, info->bssid, ETH_ALEN);
	}

	if (changed & BSS_CHANGED_ASSOC) {
		wiphy_dbg(hw->wiphy, "  ASSOC: assoc=%d aid=%d\n",
			  info->assoc, info->aid);
		vif_priv->assoc = info->assoc;
		vif_priv->aid = info->aid;
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		wiphy_dbg(hw->wiphy, "  BCN EN: %d (BI=%u)\n",
			  info->enable_beacon, info->beacon_int);
		if (data->started) {
			vif_priv->bcn_en = info->enable_beacon;		//redundant
			vif_priv->enable_beacon = info->enable_beacon;
		}
	}

	if (changed & (BSS_CHANGED_BEACON_ENABLED | BSS_CHANGED_BEACON)) {
		cancel_delayed_work_sync(&vif_priv->beacon_work);
		if (vif_priv->enable_beacon)
			schedule_work(&vif_priv->beacon_work.work);
	}

	if (changed & BSS_CHANGED_ERP_CTS_PROT) {
		wiphy_dbg(hw->wiphy, "  ERP_CTS_PROT: %d\n",
			  info->use_cts_prot);
	}

	if (changed & BSS_CHANGED_ERP_PREAMBLE) {
		wiphy_dbg(hw->wiphy, "  ERP_PREAMBLE: %d\n",
			  info->use_short_preamble);
	}

	if (changed & BSS_CHANGED_ERP_SLOT) {
		wiphy_dbg(hw->wiphy, "  ERP_SLOT: %d\n", info->use_short_slot);
	}

	if (changed & BSS_CHANGED_HT) {
		wiphy_dbg(hw->wiphy, "  HT: op_mode=0x%x\n",
			  info->ht_operation_mode);
	}

	if (changed & BSS_CHANGED_BASIC_RATES) {
		wiphy_dbg(hw->wiphy, "  BASIC_RATES: 0x%llx\n",
			  (unsigned long long) info->basic_rates);
	}

	if (changed & BSS_CHANGED_TXPOWER)
		wiphy_dbg(hw->wiphy, "  TX Power: %d dBm\n", info->txpower);

}

static int __vwlan_mac80211_sta_add(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif,
				  struct ieee80211_sta *sta)
{
	pr_info("sta_add: addr %pM\n", sta->addr);
	//hwsim_check_magic(vif);
	//hwsim_set_sta_magic(sta);

	return 0;
}

static int __vwlan_mac80211_sta_remove(struct ieee80211_hw *hw,
				     struct ieee80211_vif *vif,
				     struct ieee80211_sta *sta)
{
	pr_info("sta_remove: addr %pM\n", sta->addr);
	//hwsim_check_magic(vif);
	//hwsim_clear_sta_magic(sta);

	return 0;
}

static void __vwlan_mac80211_sta_notify(struct ieee80211_hw *hw,
				      struct ieee80211_vif *vif,
				      enum sta_notify_cmd cmd,
				      struct ieee80211_sta *sta)
{
	pr_info("sta_notify: addr %pM\n", sta->addr);
	//hwsim_check_magic(vif);

	switch (cmd) {
	case STA_NOTIFY_SLEEP:
	case STA_NOTIFY_AWAKE:
		/* TODO: make good use of these flags */
		pr_info("sta_notify: %pM sleep/awake\n", sta->addr);
		break;
	default:
		WARN(1, "Invalid sta notify: %d\n", cmd);
		break;
	}
}

static int __vwlan_mac80211_set_tim(struct ieee80211_hw *hw,
				  struct ieee80211_sta *sta,
				  bool set)
{
	pr_info("sta_tim: addr %pM???\n", sta->addr);
	//hwsim_check_sta_magic(sta);
	return 0;
}

static int __vwlan_mac80211_conf_tx(
	struct ieee80211_hw *hw,
	struct ieee80211_vif *vif, u16 queue,
	const struct ieee80211_tx_queue_params *params)
{
	wiphy_dbg(hw->wiphy,
		  "%s (queue=%d txop=%d cw_min=%d cw_max=%d aifs=%d)\n",
		  __func__, queue,
		  params->txop, params->cw_min,
		  params->cw_max, params->aifs);
	return 0;
}

static int __vwlan_mac80211_get_survey(struct ieee80211_hw *hw, int idx,
				     struct survey_info *survey)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);

	if (idx < 0 || idx >= ARRAY_SIZE(data->survey_data))
		return -ENOENT;

	mutex_lock(&data->mutex);
	survey->channel = data->survey_data[idx].channel;
	if (!survey->channel) {
		mutex_unlock(&data->mutex);
		return -ENOENT;
	}

	/*
	 * Magically conjured dummy values --- this is only ok for simulated hardware.
	 *
	 * A real driver which cannot determine real values noise MUST NOT
	 * report any, especially not a magically conjured ones :-)
	 */
	survey->filled = SURVEY_INFO_NOISE_DBM |
			 SURVEY_INFO_TIME |
			 SURVEY_INFO_TIME_BUSY;
	survey->noise = -92;
	survey->time =
		jiffies_to_msecs(data->survey_data[idx].end -
				 data->survey_data[idx].start);
	/* report 12.5% of channel time is used */
	survey->time_busy = survey->time/8;
	mutex_unlock(&data->mutex);

	return 0;
}

#if 0
static int __vwlan_mac80211_ampdu_action(struct ieee80211_hw *hw,
				       struct ieee80211_vif *vif,
				       struct ieee80211_ampdu_params *params)
{
	struct ieee80211_sta *sta = params->sta;
	enum ieee80211_ampdu_mlme_action action = params->action;
	u16 tid = params->tid;

	switch (action) {
	case IEEE80211_AMPDU_TX_START:
		ieee80211_start_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	case IEEE80211_AMPDU_TX_STOP_CONT:
	case IEEE80211_AMPDU_TX_STOP_FLUSH:
	case IEEE80211_AMPDU_TX_STOP_FLUSH_CONT:
		ieee80211_stop_tx_ba_cb_irqsafe(vif, sta->addr, tid);
		break;
	case IEEE80211_AMPDU_TX_OPERATIONAL:
		break;
	case IEEE80211_AMPDU_RX_START:
	case IEEE80211_AMPDU_RX_STOP:
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}
#endif

static void __vwlan_mac80211_flush(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 u32 queues, bool drop)
{
	pr_info("flush: clean virtqueues perhaps!!\n");
	//TODO virtqueue cleanup
	//struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
}

static u64 __vwlan_mac80211_prepare_multicast(struct ieee80211_hw *dev,
                                     struct netdev_hw_addr_list *mc_list)
{
        return netdev_hw_addr_list_count(mc_list);
}

static u64 __vwlan_mac80211_get_tsf(struct ieee80211_hw *hw,
				  struct ieee80211_vif *vif)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &info->priv;

	return le64_to_cpu(cpu_to_le64(
		ktime_to_us(ktime_get_real()) + data->tsf_offset));
}

static void __vwlan_mac80211_set_tsf(struct ieee80211_hw *hw,
		struct ieee80211_vif *vif, u64 tsf)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &info->priv;

	u64 now = __vwlan_mac80211_get_tsf(hw, vif);
	//u32 bcn_int = data->beacon_int;
	u64 delta = abs(tsf - now);

	/* adjust after beaconing with new timestamp at old TBTT */
	if (tsf > now) {
		data->tsf_offset += delta;
		//data->bcn_delta = do_div(delta, bcn_int);
	} else {
		data->tsf_offset -= delta;
		//data->bcn_delta = -(s64) do_div(delta, bcn_int);
	}
}

static const char vwlan_mac80211_gstrings_stats[][ETH_GSTRING_LEN] = {
        "tx_pkts_nic",
        "tx_bytes_nic",
        "rx_pkts_nic",
        "rx_bytes_nic",
        "d_tx_dropped",
        "d_tx_failed",
        /*"d_ps_mode",*/
        "d_group",
};

#define VWLAN_MAC80211_SSTATS_LEN ARRAY_SIZE(vwlan_mac80211_gstrings_stats)

static void __vwlan_mac80211_get_et_strings(struct ieee80211_hw *hw,
					  struct ieee80211_vif *vif,
					  u32 sset, u8 *data)
{
	if (sset == ETH_SS_STATS)
		memcpy(data, *vwlan_mac80211_gstrings_stats,
		       sizeof(vwlan_mac80211_gstrings_stats));
}

static int __vwlan_mac80211_get_et_sset_count(struct ieee80211_hw *hw,
					    struct ieee80211_vif *vif, int sset)
{
	if (sset == ETH_SS_STATS)
		return VWLAN_MAC80211_SSTATS_LEN;
	return 0;
}

static void __vwlan_mac80211_get_et_stats(struct ieee80211_hw *hw,
					struct ieee80211_vif *vif,
					struct ethtool_stats *stats, u64 *data)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	int i = 0;

	data[i++] = info->tx_pkts;
	data[i++] = info->tx_bytes;
	data[i++] = info->rx_pkts;
	data[i++] = info->rx_bytes;
	data[i++] = info->tx_dropped;
	data[i++] = info->tx_failed;
	//data[i++] = info->ps;
	//data[i++] = info->group;

	WARN_ON(i != VWLAN_MAC80211_SSTATS_LEN);
}

static void __vwlan_mac80211_sw_scan(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif,
				   const u8 *mac_addr)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);

	mutex_lock(&data->mutex);

	if (data->scanning) {
		pr_info("%s two hwsim sw_scans detected!\n", __func__);
		goto out;
	}

	pr_info("hwsim sw_scan request, prepping stuff\n");

	memcpy(data->scan_addr, mac_addr, ETH_ALEN);
	data->scanning = true;
	memset(data->survey_data, 0, sizeof(data->survey_data));

out:
	mutex_unlock(&data->mutex);
}

static void __vwlan_mac80211_sw_scan_complete(struct ieee80211_hw *hw,
					    struct ieee80211_vif *vif)
{
	struct virtwifi_info *info = (struct virtwifi_info *) hw->priv;
	struct vwlan_priv_data *data = &(info->priv);

	mutex_lock(&data->mutex);

	pr_info("hwsim sw_scan_complete\n");
	data->scanning = false;
	eth_zero_addr(data->scan_addr);

	mutex_unlock(&data->mutex);
}

static void __vwlan_beacon_work(struct work_struct *work)
{
	struct vwlan_vif_priv *vif_priv = 
		container_of(work, struct vwlan_vif_priv, beacon_work.work);
	struct ieee80211_vif *vif =
		container_of((void *) vif_priv, struct ieee80211_vif, drv_priv);
	struct vwlan_priv_data *data = vif_priv->priv;	//init in add_interface
	struct ieee80211_hw *hw = data->hw;
	struct ieee80211_mgmt *mgmt;
	struct sk_buff *skb;

	if (vif->type != NL80211_IFTYPE_AP &&
            vif->type != NL80211_IFTYPE_MESH_POINT &&
            vif->type != NL80211_IFTYPE_ADHOC)
                goto resched;

	/* don't overflow the tx ring */
        if (ieee80211_queue_stopped(hw, 0))
                goto resched;

        /* grab a fresh beacon */
        skb = ieee80211_beacon_get(hw, vif);
        if (!skb)
                goto resched;

        mgmt = (struct ieee80211_mgmt *) skb->data;
        mgmt->u.beacon.timestamp = cpu_to_le64(__vwlan_mac80211_get_tsf(hw, vif));

        /* TODO: use actual beacon queue */
        skb_set_queue_mapping(skb, 0);

        __vwlan_mac80211_tx(hw, NULL, skb);

resched:
	schedule_delayed_work(&vif_priv->beacon_work,
			usecs_to_jiffies(1024 * vif->bss_conf.beacon_int));
}

static const struct ieee80211_ops virt_mac80211_ops = {
	.tx			= __vwlan_mac80211_tx,		//TODO
	.start 			= __vwlan_mac80211_start,
	.stop 			= __vwlan_mac80211_stop,
	.add_interface 		= __vwlan_mac80211_add_interface,
	.change_interface	= __vwlan_mac80211_change_interface,	//??
	.remove_interface 	= __vwlan_mac80211_remove_interface,
	.config 		= __vwlan_mac80211_config,
	.configure_filter 	= __vwlan_mac80211_configure_filter,
	.bss_info_changed 	= __vwlan_mac80211_bss_info_changed,
	.sta_add 		= __vwlan_mac80211_sta_add,
	.sta_remove 		= __vwlan_mac80211_sta_remove,
	.sta_notify 		= __vwlan_mac80211_sta_notify,
	.set_tim 		= __vwlan_mac80211_set_tim,
	.conf_tx 		= __vwlan_mac80211_conf_tx,
	.get_survey 		= __vwlan_mac80211_get_survey,
	/* .ampdu_action 		= __vwlan_mac80211_ampdu_action, */
	.flush 			= __vwlan_mac80211_flush,
	.prepare_multicast	= __vwlan_mac80211_prepare_multicast,
	.get_tsf 		= __vwlan_mac80211_get_tsf,
	.set_tsf 		= __vwlan_mac80211_set_tsf,
	.get_et_sset_count 	= __vwlan_mac80211_get_et_sset_count,
	.get_et_stats 		= __vwlan_mac80211_get_et_stats,
	.get_et_strings 	= __vwlan_mac80211_get_et_strings,
	.sw_scan_start 		= __vwlan_mac80211_sw_scan,
	.sw_scan_complete 	= __vwlan_mac80211_sw_scan_complete,
};

//-----------------virtio_driver impl-----------------------
static void __free_old_xmit_skbs(struct virtwifi_info *vi, struct send_queue *sq)
{
	struct sk_buff *skb;
	unsigned int bytes = 0;
	unsigned int pkts = 0;
	unsigned int len = 0;

	while ((skb = virtqueue_get_buf(sq->vq, &len)) != NULL) {
		pr_info("%s: sent skb %p\n", __func__, skb);
		//increment counters
		bytes += skb->len;
		pkts++;

		dev_consume_skb_any(skb);
	}

	//update tx stats
	vi->tx_bytes += bytes;
	vi->tx_pkts += pkts;
}

static bool try_fill_recv(struct virtwifi_info *vi, struct receive_queue *rq,
                          gfp_t gfp)
{
	bool oom;
	do {
		struct page_frag *alloc_frag = &rq->alloc_frag;
		char *buf;
		int len = VIRTIO_MAC80211_BUF_LEN;
		int err;

		if (unlikely(!skb_page_frag_refill(len, alloc_frag, gfp))) {
			err = -ENOMEM;
			goto err_refill;
		}

		buf = (char *) page_address(alloc_frag->page) + alloc_frag->offset;
		get_page(alloc_frag->page);
		alloc_frag->offset += len;
		sg_init_one(rq->sg, buf + VIRTMAC80211_RX_PAD, 
			GOOD_MAC80211_PACKET_LEN);
		err = virtqueue_add_inbuf(rq->vq, rq->sg, 1, buf, gfp);
		if (err < 0)
			put_page(virt_to_head_page(buf));
err_refill:
		oom = err == -ENOMEM;
		if (err)
			break;
	} while (rq->vq->num_free);
	virtqueue_kick(rq->vq);
	return !oom;
}

//TODO: this is to fill up receive queue with buffers
static void refill_work(struct work_struct *work)
{
	struct virtwifi_info *vi =
		container_of(work, struct virtwifi_info, refill.work);
	struct receive_queue *rq = &vi->rq[DEFAULT_VIRTQUEUE];

	if (!try_fill_recv(vi, rq, GFP_KERNEL))
		schedule_delayed_work(&vi->refill, HZ/2);
}

static unsigned int __receive_packet(struct virtwifi_info *info, 
					struct receive_queue *rq,
					void *buf, unsigned int len)
{
	unsigned int plen = 0;
	struct sk_buff *skb;
	struct page *page = virt_to_head_page(buf);
	struct ieee80211_rx_status rx_status = { 0 };

	if (unlikely(len < MAX_MAC80211_HLEN)) {
		pr_err("%s: short packet %d\n", __func__, len);
		//info->rx_dropped++;
		put_page(page);
		return 0;
	}
	
	skb = build_skb(buf, VIRTIO_MAC80211_BUF_LEN);
	if (!skb) {
		put_page(page);
		return 0;
	}
	skb_reserve(skb, VIRTMAC80211_RX_PAD);
	skb_put(skb, len);

	plen = skb->len;

	memset(&rx_status, 0, sizeof(rx_status));
	//TODO: use proper values!!
	rx_status.antenna = 0x00;
	rx_status.rate_idx = 0x00;
	rx_status.signal = 0x00;
	rx_status.freq = 0x00;
	rx_status.mactime = 0x00;
	rx_status.band = 0x00;
	rx_status.flag = 0x00;
	rx_status.enc_flags = 0x00;

	memcpy(IEEE80211_SKB_RXCB(skb), &rx_status, sizeof(rx_status));

	ieee80211_rx_irqsafe(info->priv.hw, skb);

	return plen;
}

static int __virtwifi_receive(struct virtwifi_info *vi, struct receive_queue *rq)
{
	void *buf;
	unsigned int len, bytes = 0;

	buf = virtqueue_get_buf(rq->vq, &len);
	if (buf)
		bytes = __receive_packet(vi, rq, buf, len);

	//TODO update once refill_work is complete
	if (rq->vq->num_free > (virtqueue_get_vring_size(rq->vq) / 2)) {
		if (!try_fill_recv(vi, rq, GFP_ATOMIC))
			schedule_delayed_work(&vi->refill, 0);
	}

	return bytes;
}

//start of receive packet path, same as receive interrupt in other drivers
static void __virtwifi_rx_handler_cb(struct virtqueue *vq)
{
	struct virtwifi_info *info = (struct virtwifi_info *) vq->vdev->priv;
	struct receive_queue *rq = &info->rq[DEFAULT_VIRTQUEUE];

	unsigned int bytes;

	bytes = __virtwifi_receive(info, rq);

	//stats update
	//spin lock
	info->rx_pkts++;
	info->rx_bytes += bytes;
	//spin unlock
}

static void __virtwifi_tx_handler_cb(struct virtqueue *vq)
{
	//TODO: identify what goes here!!!
	//__free_old_xmit_skbs(sq);
	virtqueue_disable_cb(vq);	//for now only disabling xmit intr
}

static inline int __virtwifi_find_vqs(struct virtwifi_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int ret = -ENOMEM;

	int total_vqs;
	const char **names;
	bool *ctx;

	/* We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by
	 * possible N-1 RX/TX queue pairs used in multiqueue mode, followed by
	 * possible control vq.
	 */
	total_vqs = vi->max_queue_pairs * 2;
	if (vi->has_cvq)
		total_vqs += 1;

	/* Allocate space for find_vqs parameters */
	vqs = kzalloc(total_vqs * sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc(total_vqs * sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc(total_vqs * sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;

	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		ctx = kzalloc(total_vqs * sizeof(*ctx), GFP_KERNEL);
		if (!ctx)
			goto err_ctx;
	} else {
		ctx = NULL;
	}

	/* Parameters for control virtqueue, if any */
	if (vi->has_cvq) {
		callbacks[total_vqs - 1] = NULL;
		names[total_vqs - 1] = "control";
	}

	/* Allocate/initialize parameters for send/receive virtqueues */
	callbacks[0] = __virtwifi_rx_handler_cb;
	sprintf(vi->rq[DEFAULT_VIRTQUEUE].name, "input.0");
	names[0] = vi->rq[DEFAULT_VIRTQUEUE].name;

	callbacks[1] = __virtwifi_tx_handler_cb;
	sprintf(vi->sq[DEFAULT_VIRTQUEUE].name, "output.0");
	names[1] = vi->sq[DEFAULT_VIRTQUEUE].name;

	if (ctx)
		ctx[0] = true;

	ret = vi->vdev->config->find_vqs(vi->vdev, total_vqs, vqs, callbacks,
			names, ctx, NULL);
	if (ret)
		goto err_find;

	if (vi->has_cvq) {
		vi->cvq = vqs[total_vqs - 1];
	}
	vi->rq[DEFAULT_VIRTQUEUE].vq = vqs[0];
	vi->rq[DEFAULT_VIRTQUEUE].min_buf_len = GOOD_MAC80211_PACKET_LEN;
	vi->sq[DEFAULT_VIRTQUEUE].vq = vqs[1];

	kfree(names);
	kfree(callbacks);
	kfree(vqs);
	kfree(ctx);

	return 0;

err_find:
	kfree(ctx);
err_ctx:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static inline int __virtwifi_alloc_queues(struct virtwifi_info *vi)
{
	int i;

	vi->sq = kzalloc(sizeof(*vi->sq) * vi->max_queue_pairs, GFP_KERNEL);
	if (!vi->sq)
		goto err_sq;
	vi->rq = kzalloc(sizeof(*vi->rq) * vi->max_queue_pairs, GFP_KERNEL);
	if (!vi->rq)
		goto err_rq;
		
	INIT_DELAYED_WORK(&vi->refill, refill_work);

	//XXX max_queue_pairs = 1
	for (i = 0; i < vi->max_queue_pairs; i++) {
                vi->rq[i].pages = NULL;
#if 0
                netif_napi_add(vi->dev, &vi->rq[i].napi, virtnet_poll,
                               napi_weight);
                netif_tx_napi_add(vi->dev, &vi->sq[i].napi, virtnet_poll_tx,
                                  napi_tx ? napi_weight : 0);
#endif

                sg_init_table(vi->rq[i].sg, ARRAY_SIZE(vi->rq[i].sg));
                //ewma_pkt_len_init(&vi->rq[i].mrg_avg_pkt_len);
                sg_init_table(vi->sq[i].sg, ARRAY_SIZE(vi->sq[i].sg));
        }

	return 0;
err_rq:
	kfree(vi->sq);
err_sq:
	return -ENOMEM;
}

static int __virtwifi_init_queues(struct virtwifi_info *vi)
{
	//allocate and initialize virtqueues, only one pair currently supoorted
	int ret = 0;

	ret = __virtwifi_alloc_queues(vi);
	if (ret)
		goto err;

	ret = __virtwifi_find_vqs(vi);
	if (ret)
		goto err_free;

	//unlike virtnet, no cpu affinity here
	return 0;

err_free:
	//__virtwifi_free_vqs(vi);	//TODO
err:
	return ret;
}

static int virtwifi_validate(struct virtio_device *vdev)
{
	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
				__func__);
		return -EINVAL;
	}

	pr_info("%s: no feature validation!!!\n", __func__);

	return 0;
}

//new radio (vwlanX)
static int virtwifi_probe(struct virtio_device *_v)
{
	int err = -ENOMEM;
	int idx = 0;
	enum nl80211_band band;
	struct ieee80211_hw *hw;
	struct virtwifi_info *info;	//virtio 
	struct vwlan_priv_data *data;	//mac80211
	//struct net *net;
	u8 addr[ETH_ALEN] = { 0 };
	char hwname[IFNAMSIZ] = { 0 };

	spin_lock_bh(&vwlan_radio_lock);
	idx = vwlan_radio_idx++;
	spin_unlock_bh(&vwlan_radio_lock);

	snprintf(hwname, IFNAMSIZ, "vwlan%d", idx);

	//as # channels = 1, no multi-channel ops required
	hw = ieee80211_alloc_hw_nm(sizeof(*info), &virt_mac80211_ops, hwname);
	if (!hw) {
		pr_err("virtwifi_probe: ieee80211_alloc_hw_nm failed to allocate.\n");
		return -ENOMEM;
	}

	wiphy_net_set(hw->wiphy, &init_net);

	info = (struct virtwifi_info *) hw->priv;
	info->vdev = _v;
	_v->priv = info;

	data = &(info->priv);
	data->hw = hw;

	skb_queue_head_init(&data->pending);

	SET_IEEE80211_DEV(hw, &(_v->dev)); //virtio_device->device
	//TODO:  important read MAC address from virtio device
	//virtio_cread_bytes(_v, offsetof(), addr, ETH_ALEN);
	//eth_zero_addr(addr);
	eth_random_addr(addr);
	//addr[0] = 0x02;
	addr[3] = idx >> 8;
	addr[4] = idx;
	memcpy(data->addresses[0].addr, addr, ETH_ALEN);
	memcpy(data->addresses[1].addr, addr, ETH_ALEN);
	data->addresses[1].addr[0] |= 0x40;

	hw->wiphy->n_addresses = 2;
	hw->wiphy->addresses = data->addresses;

	data->channels = VIRTWIFI_CHANNELS_MAX;
	data->use_chanctx = false;
	//data->use_chanctx = (data->channels > 1);	//XXX always false

	data->idx = idx;
	data->destroy_on_close = 0;

	hw->wiphy->iface_combinations = vwlan_mac80211_comb;
	hw->wiphy->n_iface_combinations = ARRAY_SIZE(vwlan_mac80211_comb);

#if 0
	//TODO remain-on-channel do we need in this imple??
	INIT_DELAYED_WORK(&_p->roc_start, __vwlan_roc_start);
        INIT_DELAYED_WORK(&_p->roc_done, __vwlan_roc_done);
        INIT_DELAYED_WORK(&_p->hw_scan, __vwlan_scan_work);
#endif

	hw->queues = 5;		//????
	hw->offchannel_tx_hw_queue = 4;
        hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) |
                                     BIT(NL80211_IFTYPE_AP);

	ieee80211_hw_set(hw, SUPPORT_FAST_XMIT);
        //ieee80211_hw_set(hw, CHANCTX_STA_CSA);
        ieee80211_hw_set(hw, SUPPORTS_HT_CCK_RATES);
        ieee80211_hw_set(hw, QUEUE_CONTROL);
        //ieee80211_hw_set(hw, WANT_MONITOR_VIF);
        //ieee80211_hw_set(hw, AMPDU_AGGREGATION);
        ieee80211_hw_set(hw, MFP_CAPABLE);
        ieee80211_hw_set(hw, SIGNAL_DBM);
        ieee80211_hw_set(hw, TDLS_WIDER_BW);

	hw->wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS |
                            WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL |
                            WIPHY_FLAG_AP_UAPSD |
                            WIPHY_FLAG_HAS_CHANNEL_SWITCH;
        hw->wiphy->features |= NL80211_FEATURE_ACTIVE_MONITOR |
                               NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE |
                               NL80211_FEATURE_STATIC_SMPS |
                               NL80211_FEATURE_DYNAMIC_SMPS |
                               NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR;
        wiphy_ext_feature_set(hw->wiphy, NL80211_EXT_FEATURE_VHT_IBSS);

	/* ask mac80211 to reserve space for magic */
        hw->vif_data_size = sizeof(struct vwlan_vif_priv);
        hw->sta_data_size = sizeof(struct vwlan_sta_priv);
        hw->chanctx_data_size = sizeof(struct vwlan_chanctx_priv);

        memcpy(data->channels_2ghz, vwlan_channels_2ghz,
                sizeof(vwlan_channels_2ghz));
        memcpy(data->channels_5ghz, vwlan_channels_5ghz,
                sizeof(vwlan_channels_5ghz));
        memcpy(data->rates, vwlan_rates, sizeof(vwlan_rates));

	for (band = NL80211_BAND_2GHZ; band < NUM_NL80211_BANDS; band++) {
                struct ieee80211_supported_band *sband = &data->bands[band];
                switch (band) {
                case NL80211_BAND_2GHZ:
                        sband->channels = data->channels_2ghz;
                        sband->n_channels = ARRAY_SIZE(vwlan_channels_2ghz);
                        sband->bitrates = data->rates;
                        sband->n_bitrates = ARRAY_SIZE(vwlan_rates);
                        break;
                case NL80211_BAND_5GHZ:
                        sband->channels = data->channels_5ghz;
                        sband->n_channels = ARRAY_SIZE(vwlan_channels_5ghz);
                        sband->bitrates = data->rates + 4;
                        sband->n_bitrates = ARRAY_SIZE(vwlan_rates) - 4;

                        sband->vht_cap.vht_supported = true;
                        sband->vht_cap.cap =
                                IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454 |
                                IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ |
                                IEEE80211_VHT_CAP_RXLDPC |
                                IEEE80211_VHT_CAP_SHORT_GI_80 |
                                IEEE80211_VHT_CAP_SHORT_GI_160 |
                                IEEE80211_VHT_CAP_TXSTBC |
                                IEEE80211_VHT_CAP_RXSTBC_1 |
                                IEEE80211_VHT_CAP_RXSTBC_2 |
                                IEEE80211_VHT_CAP_RXSTBC_3 |
                                IEEE80211_VHT_CAP_RXSTBC_4 |
                                IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
                        sband->vht_cap.vht_mcs.rx_mcs_map =
                                cpu_to_le16(IEEE80211_VHT_MCS_SUPPORT_0_9 << 0 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 2 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 4 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 6 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 8 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 10 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 12 |
                                            IEEE80211_VHT_MCS_SUPPORT_0_9 << 14);
                        sband->vht_cap.vht_mcs.tx_mcs_map =
                                sband->vht_cap.vht_mcs.rx_mcs_map;
                        break;
                default:
                        continue;
                }

                sband->ht_cap.ht_supported = true;
                sband->ht_cap.cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 |
                                    IEEE80211_HT_CAP_GRN_FLD |
                                    IEEE80211_HT_CAP_SGI_20 |
                                    IEEE80211_HT_CAP_SGI_40 |
                                    IEEE80211_HT_CAP_DSSSCCK40;
                sband->ht_cap.ampdu_factor = 0x3;
                sband->ht_cap.ampdu_density = 0x6;
		memset(&sband->ht_cap.mcs, 0,
                       sizeof(sband->ht_cap.mcs));
                sband->ht_cap.mcs.rx_mask[0] = 0xff;
                sband->ht_cap.mcs.rx_mask[1] = 0xff;
                sband->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;

                hw->wiphy->bands[band] = sband;
        }

	mutex_init(&data->mutex);
	data->group = 1;
	//data->netgroup = hwsim_net_get_netgroup(net);	//????

	/* Enable frame retransmissions for lossy channels */
        hw->max_rates = 4;
        hw->max_rate_tries = 11;

#if 0
        hw->wiphy->vendor_commands = mac80211_hwsim_vendor_commands;		//TODO
        hw->wiphy->n_vendor_commands =
                ARRAY_SIZE(mac80211_hwsim_vendor_commands);
        hw->wiphy->vendor_events = mac80211_hwsim_vendor_events;		//TODO
        hw->wiphy->n_vendor_events = ARRAY_SIZE(mac80211_hwsim_vendor_events);
#endif

	wiphy_ext_feature_set(hw->wiphy, NL80211_EXT_FEATURE_CQM_RSSI_LIST);

	err = ieee80211_register_hw(hw);
	if (err < 0) {
		pr_err("virtwifi_probe: ieee80211_register_hw failed (%d)\n",
			err);
		goto failed_hw;
	}
	wiphy_dbg(hw->wiphy, "hwaddr %pM registered\n", hw->wiphy->perm_addr);

	data->debugfs = debugfs_create_dir("virtwifi", hw->wiphy->debugfsdir);
	//debugfs_create_file("ps", 0666, data->debugfs, data, &hwsim_fops_ps);	//TODO

	spin_lock_bh(&vwlan_radio_lock);
	list_add_tail(&info->list, &vwlan_radios);
	spin_unlock_bh(&vwlan_radio_lock);

	info->max_queue_pairs = VIRTWIFI_MAX_QUEUE_PAIR;
	info->big_packets = false;	//no big packet support
	info->mergeable_rx_bufs = false;	//host to merge rx buffers for big packet?!?!
	info->hdr_len = 0;
	info->has_cvq = true;
	info->any_header_sg = false;

	err = __virtwifi_init_queues(info);
	if (err)
		goto failed_vqs;


	pr_info("virtwifi_probe: new virtio radio created: %s %pM\n", hwname, 
			hw->wiphy->perm_addr);
	return 0;

failed_vqs:
	//info->vdev->config->reset(vdev);	//TODO
	//delete_multicast();
	debugfs_remove_recursive(data->debugfs);
	ieee80211_unregister_hw(hw);
failed_hw:
	ieee80211_free_hw(hw);
	return err;
}

static void virtwifi_remove(struct virtio_device *vdev)
{
	struct virtwifi_info *info = vdev->priv;

	spin_lock_bh(&vwlan_radio_lock);
	//TODO
	//1. free unused bufs
	//2. free send/receive bufs
	//3. virnet_del_vqs()
	//4. free virtwifi_info
	//info->vdev->config->reset(vdev);

	debugfs_remove_recursive(info->priv.debugfs);

	ieee80211_unregister_hw(info->priv.hw);
	ieee80211_free_hw(info->priv.hw);

	spin_unlock_bh(&vwlan_radio_lock);
}

static void virtwifi_config_changed(struct virtio_device *vdev)
{
	pr_info("%s: TODO\n", __func__);
}

static __maybe_unused int virtwifi_freeze(struct virtio_device *vdev)
{
#if 0
        struct virtwifi_info *vi = vdev->priv;
        virtnet_cpu_notif_remove(vi);
        virtnet_freeze_down(vdev);
        remove_vq_common(vi);
#endif
        return 0;
}

static __maybe_unused int virtwifi_restore(struct virtio_device *vdev)
{
#if 0
        struct virtwifi_info *vi = vdev->priv;
        int err;
        err = virtnet_restore_up(vdev);
        if (err)
                return err;
        virtnet_set_queues(vi, vi->curr_queue_pairs);

        err = virtnet_cpu_notif_add(vi);
        if (err)
                return err;
#endif
        return 0;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_MAC80211, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

/*
 * TODO: currently no features are implemented!!
 */
#define VIRTWIFI_FEATURES \
	VIRTIO_MAC80211_F_MAC, \
	VIRTIO_MAC80211_F_MTU

static unsigned int features[] = {
	VIRTWIFI_FEATURES,
};

static struct virtio_driver virtio_mac80211_driver = {
	.feature_table 		= 	features,
	.feature_table_size 	= 	ARRAY_SIZE(features),
	.driver.name 		=	KBUILD_MODNAME,
	.driver.owner 		=	THIS_MODULE,
	.id_table 		=	id_table,
	.validate 		=	virtwifi_validate,
	.probe 			=	virtwifi_probe,
	.remove 		=	virtwifi_remove,
	.config_changed 	= 	virtwifi_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze 		=	virtwifi_freeze,
	.restore 		=	virtwifi_restore,
#endif
};

static int __init __init_virtwifi(void)
{
	int err = 0;

	spin_lock_init(&vwlan_radio_lock);

	err = register_virtio_driver(&virtio_mac80211_driver);
	if (err) {
		err = -ENOTSUPP;
		goto err_driver;
	}

	pr_info("registered MAC802.11 virtio frontend driver...\n");

#if 0
	//add radiotap here TODO
	hwsim_mon = alloc_netdev();
	if (!hwsim_mon) {
		err = -ENOMEM;
		goto out_unregister_driver;
	}

	rtnl_lock();
	dev_alloc_name();	//TODO
	err = register_netdevice(hwsim_mon);
	if (err < 0) {
		rtnl_unlock();
		goto out_free_hwmon;
	}
	rtnl_unlock();
#endif
	return 0;

#if 0
out_free_hwmon:
	free_netdev(hwsim_mon);
out_unregister_driver:
	unregister_virtio_driver(&virtio_mac80211_driver);
#endif
err_driver:
	return err;
}
module_init(__init_virtwifi);

static void __exit __exit_virtwifi(void)
{
	pr_info("%s: XXXXXXX breaking point!!\n", __func__);
	panic("XXXXX TODO clear resources properly XXXXX\n");
	//unregister_virtio_driver(&virtio_mac80211_driver);
}
module_exit(__exit_virtwifi);

MODULE_AUTHOR("Ratnaraj Mirgal<ratnaraj.mirgal@gmail.com>");
MODULE_DESCRIPTION("Virtio frontend driver for 802.11 radio(s)");
MODULE_LICENSE("GPL");
