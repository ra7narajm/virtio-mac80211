obj-m += virtio_mac80211.o

all:
	make -C $(LINUX_DIR) M=$(BR2_EXTERNAL_VIRTIO_MAC80211_PATH) modules

clean:
	make -C $(LINUX_DIR) M=$(BR2_EXTERNAL_VIRTIO_MAC80211_PATH) clean

sabuild:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

saclean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
