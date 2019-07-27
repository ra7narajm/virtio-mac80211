/*
 * Connectivity to Wifi emulated medium (only for virtio-mac80211)
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <net/if.h>

#include "monitor/monitor.h"
#include "net/net.h"
#include "clients.h"
#include "airport.h"
#include "qemu/iov.h"
#include "qemu/error-report.h"
#include "qemu-common.h"
#include "qemu/option.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "sysemu/qtest.h"

#include <syslog.h>

//NOTE: VDE implementation used for reference

#define WIFIMEDIUM_SERVER_SOCK		"/tmp/wifimedium_data.%u.sock"

#define WIFIMEDIUM_MAX_PORTS	8	//TODO support upto 128
#define WIFIMEDIUM_MAX_FRAME	4096	//should be VIRTIO_MAC80211_BUF_LEN

struct ctrl_iov {
	int8_t mode;		//0 = new port, 1 = wifi packet
	int8_t hubid;
	int16_t portid;
};

//wifi buffer
typedef struct __wifi_iov {
	struct ctrl_iov __iov;
	uint8_t frame[WIFIMEDIUM_MAX_FRAME];
} wifi_iov;

struct port_data {
	struct ctrl_iov __iov;
	//int ctrlsock;
	int datasock;
};

typedef struct NetAirPort {
    NetClientState nc;
    QLIST_ENTRY(NetAirPort) next;

    struct port_data data;

    wifi_iov sndbuf;
    wifi_iov rcvbuf;
} NetAirPort;

static QLIST_HEAD(, NetAirPort) ports = QLIST_HEAD_INITIALIZER(&ports);

//wifi medium-to-vm, TODO: set qemu_set_fd_handler for socket
static void __recv_from_wifimedium(void *op)
{
    NetAirPort *port = (NetAirPort *) op;
    uint8_t *buf = &port->rcvbuf;
    int size = 0;

    bzero(buf, sizeof(wifi_iov));

    syslog(LOG_ERR, "XXXXX __recv_from_wifimedium invoked..\n");

    size = recv(port->data.datasock, &port->rcvbuf, sizeof(wifi_iov), 0);
    if (size && port->rcvbuf.__iov.mode) {
	    syslog(LOG_ERR, "XXXXX packet received from port: %d\n", port->rcvbuf.__iov.portid);
	    qemu_send_packet(&port->nc, port->rcvbuf.frame, (size - offsetof(wifi_iov, frame)));
    } else {
	    syslog(LOG_ERR, "XXXXX __recv_from_wifimedium: received packet size: %u and mode: %u\n", size, port->rcvbuf.__iov.mode);
    }
}

// vm-to- wifi medium
static ssize_t net_wifi_port_receive(NetClientState *nc,
                                    const uint8_t *buf, size_t len)
{
    NetAirPort *port = DO_UPCAST(NetAirPort, nc, nc);
    ssize_t ret;

    syslog(LOG_ERR, "XXXXX net_wifi_port_receive out buffer len: %ld\n", len);

    //TODO: use sndbuf
    memcpy(port->sndbuf.frame, buf, len);

    do {
	    ret = send(port->data.datasock, &port->sndbuf, (len + offsetof(wifi_iov, frame)), 0);
	    syslog(LOG_ERR, "net_wifi_port_receive: %d  mode: %d hubid: %d portid: %d\n", ret,
	    	port->sndbuf.__iov.mode, port->sndbuf.__iov.hubid, port->sndbuf.__iov.portid);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

static void net_wifi_clean_port(struct port_data *data)
{
	struct ctrl_iov ctio;
	//inform server about closing
	ctio.mode = 0;
	ctio.hubid = data->__iov.hubid;
	ctio.portid = data->__iov.portid;

	//send close
	close(data->datasock);
}

static void net_wifi_port_cleanup(NetClientState *nc)
{
    NetAirPort *port = DO_UPCAST(NetAirPort, nc, nc);

    qemu_set_fd_handler(port->data.datasock, NULL, NULL, NULL);
    net_wifi_clean_port(&port->data);

    QLIST_REMOVE(port, next);
}

static NetClientInfo net_wifi_port_info = {
    .type = NET_CLIENT_DRIVER_AIRPORT,
    .size = sizeof(NetAirPort),
    .receive = net_wifi_port_receive,
    .cleanup = net_wifi_port_cleanup,
};

static NetAirPort *net_wifi_port_new(struct port_data *data, const char *name,
                                    NetClientState *peer)
{
    NetClientState *nc;
    NetAirPort *port;

    //int id = hub->num_ports++;
    char default_name[128];

    if (!name) {
        snprintf(default_name, sizeof(default_name),
                 "wifi%dport%d", data->__iov.hubid, data->__iov.portid);
        name = default_name;
    }

    nc = qemu_new_net_client(&net_wifi_port_info, peer, "airport", name);
    port = DO_UPCAST(NetAirPort, nc, nc);

    port->data.__iov.portid = data->__iov.portid;
    port->data.__iov.hubid = data->__iov.hubid;

    port->data.datasock = data->datasock;

    port->sndbuf.__iov.mode = 1;
    port->sndbuf.__iov.hubid = data->__iov.hubid;
    port->sndbuf.__iov.portid = data->__iov.portid;

    QLIST_INSERT_HEAD(&ports, port, next);

    return port;
}

static int net_wifi_connect(struct port_data *data)
{
    struct sockaddr_un data_sockaddr;
    char path[64] = { 0 };

    struct ctrl_iov ciov;
    int ret = 0;

    data->datasock = -EINVAL;

    {
	    sprintf(path, WIFIMEDIUM_SERVER_SOCK, data->__iov.hubid);

	    data->datasock = socket(AF_UNIX, SOCK_STREAM, 0);
	    if (data->datasock < 0) {
		    syslog(LOG_ERR, "socket error\n");
		    return -1;
	    }
	    bzero(&data_sockaddr, sizeof(struct sockaddr_un));

	    data_sockaddr.sun_family = AF_UNIX;
	    strcpy(data_sockaddr.sun_path, path);

	    if (connect(data->datasock, (struct sockaddr *) &data_sockaddr, sizeof(struct sockaddr_un)) < 0) {
		    syslog(LOG_ERR, "connect error\n");
		    close(data->datasock);
		    return -1;
	    }

	    //send hubid and read portid
	    ciov.mode = 0;
	    ciov.hubid = data->__iov.hubid;
	    ciov.portid = 0;

	    ret = send(data->datasock, &ciov, sizeof(struct ctrl_iov), 0);
	    if (ret < sizeof(struct ctrl_iov)) {
	    }

	    ret = recv(data->datasock, &ciov, sizeof(struct ctrl_iov), 0);
	    if (ret < sizeof(struct ctrl_iov)) {
	    }

	    if (ciov.portid < 0) {
	    }
	    syslog(LOG_ERR, "XXXXX wifimedium %s conneted on port %d\n", path, ciov.portid);

	    data->__iov.portid = ciov.portid;
    }

    return data->datasock;
}

static int net_wifi_add_port(int hub_id, const char *name,
                                 NetClientState *peer)
{
    NetAirPort *p;
    struct port_data data;

    bzero(&data, sizeof(struct port_data));
    data.__iov.hubid = hub_id;

    if (net_wifi_connect(&data) < 0) {
	    syslog(LOG_ERR, "XXXXX unable to connect to wifi medium!!\n");
	    return -1;
    }

    p = net_wifi_port_new(&data, name, peer);
    if (!p) {
	    syslog(LOG_ERR, "unable to create new port\n");
	    net_wifi_clean_port(&data);
	    return -1;
    }

    qemu_set_fd_handler(data.datasock, __recv_from_wifimedium, NULL, p);

    return 0;
}

int net_init_airport(const Netdev *netdev, const char *name,
                     NetClientState *peer, Error **errp)
{
    const NetdevAirPortOptions *airport;

    assert(netdev->type == NET_CLIENT_DRIVER_AIRPORT);
    airport = &netdev->u.airport;

    syslog(LOG_ERR, "net_init_airport: new port on wifi %d\n", airport->termid);

    //return 0 (success), -1 (error)
    return net_wifi_add_port(airport->termid, name, peer);
}
