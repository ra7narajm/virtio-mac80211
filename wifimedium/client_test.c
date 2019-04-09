#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <syslog.h>

#include "dlist.h"

//TODO: this is to be used for testing and as monitor port

#define WIFIMEDIUM_SERVER_SOCK          "/tmp/wifimedium_data.%u.sock"

#define WIFIMEDIUM_MAX_FRAME    4096    //should be VIRTIO_MAC80211_BUF_LEN

#define NO_SOCKET       -1

struct ctrl_iov {
        int8_t mode;           //0 = new port, 1 = wifi packet
        int8_t hubid;
        int16_t portid;
};

//wifi buffer
typedef struct __wifi_iov {
        struct ctrl_iov __iov;
        char frame[WIFIMEDIUM_MAX_FRAME];
} wifi_iov;

struct port_data {
        struct ctrl_iov __iov;
        //int ctrlsock;
        int datasock;
};

typedef struct air_port {
    struct port_data data;

    wifi_iov sndbuf;
    wifi_iov rcvbuf;
} air_port;

struct air_port cliport;

int main (int argc, char **argv)
{
	struct sockaddr_un data_sockaddr;
	unsigned int tid = 20;
	char path[64] = { 0 };
	struct ctrl_iov ciov;
	int ret = 0;

	cliport.data.__iov.hubid = tid;

	sprintf(path, WIFIMEDIUM_SERVER_SOCK, tid);

	cliport.data.datasock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cliport.data.datasock < 0) {
		printf("socket error\n");
		return -EINVAL;
	}
	bzero(&data_sockaddr, sizeof(struct sockaddr_un));

	data_sockaddr.sun_family = AF_UNIX;
	strcpy(data_sockaddr.sun_path, path);

	if (connect(cliport.data.datasock, (struct sockaddr *) &data_sockaddr, sizeof(struct sockaddr_un)) < 0) {
		printf("connect error\n");
		close(cliport.data.datasock);
		return -EINVAL;
	}

	ciov.mode = 0;
	ciov.hubid = tid;
	ciov.portid = 0;

	ret = send(cliport.data.datasock, &ciov, sizeof(struct ctrl_iov), 0);
	if (ret < sizeof(struct ctrl_iov)) {
	}

	ret = recv(cliport.data.datasock, &ciov, sizeof(struct ctrl_iov), 0);
	if (ret < sizeof(struct ctrl_iov)) {
	}

	if (ciov.portid < 0) {
		printf("port id not received!!!\n");
	}
	printf("wifimedium %s conneted on port %d\n", path, ciov.portid);

	return 0;
}
