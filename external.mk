################################################################################
#
# virtio-mac80211 buildroot external package make-file
#
################################################################################

VIRTIO_MAC80211_VERSION = 1.0
VIRTIO_MAC80211_SITE = $(BR2_EXTERNAL_VIRTIO_MAC80211_PATH)
VIRTIO_MAC80211_SITE_METHOD = local
VIRTIO_MAC80211_LICENSE = GPL-2.0
VIRTIO_MAC80211_LICENSE_FILES = COPYING
#VIRTIO_MAC80211_MODULE_MAKE_OPTS = 

$(eval $(kernel-module))
$(eval $(generic-package))
