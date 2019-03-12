//wireless medium : to connect wireless ports of VMs
//TODO: single-to-noise implementation

/*
 * step 1. client connect, send hubid, return unique portid
 * step 2. send-receive frame [ hubid | portid | mac802.11 frame ]
 */

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

#include <syslog.h>

#include "dlist.h"

//#define WIFIMEDIUM_SERVER_CTRLSOCK      "/tmp/wifimedium_ctrl.server"
//#define WIFIMEDIUM_SERVER_DATASOCK      "/tmp/wifimedium_data.server"

#define WIFIMEDIUM_SERVER_SOCK		"/tmp/wifimedium_data.%u.sock"

#define WIFIMEDIUM_MAX_PORTS    8       //TODO support upto 128
#define WIFIMEDIUM_MAX_FRAME    4096    //should be VIRTIO_MAC80211_BUF_LEN

#define NO_SOCKET	-1

struct ctrl_iov {
        int8_t mode;           //0 = new port, 1 = wifi packet
        int8_t hubid;
        int16_t portid;
};

//wifi buffer
struct wifi_iov {
	struct ctrl_iov __iov;
	char frame[WIFIMEDIUM_MAX_FRAME];
};

struct air_port {
	//struct list_head node;
	int clisock;
	int32_t portid;
	//struct wifi_iov sndbuf;
	struct wifi_iov rcvbuf;
};

struct wifi_hub {
	//struct list_head node;
	int32_t hubid;
	int32_t num_ports;
	//struct list_head head;	//TODO implement as port list
	struct air_port ports[WIFIMEDIUM_MAX_PORTS];
};

#define WIFIMEDIUM_MAX_HUBS	2

struct wifimedium_global {
	int ctrlsock;
	//int datasock;
	//struct sockaddr_un server_sockaddr;
	//struct list_head head;
	//struct wifi_hub hubs[WIFIMEDIUM_MAX_HUBS];	//TODO as hub list
	struct wifi_hub hub;
};

struct wifimedium_global wmedium;

//----------------------------------------------------------------------------------------
static int __create_server_socket(char *path)
{
	int sock;
	struct sockaddr_un sockaddr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("socket error: %s\n", path);
		return sock;
	}
	bzero(&sockaddr, sizeof(struct sockaddr_un));

	sockaddr.sun_family = AF_UNIX;
	strcpy(sockaddr.sun_path, path);
	unlink(path);

	if (bind(sock, (struct sockaddr *) &sockaddr, sizeof(struct sockaddr_un)) < 0) {
	}

	if (listen(sock, 8) < 0) {
	}

	printf("now listening unix socket %s\n", path);

	return sock;
}

#define hubport 	wmedium.hub.ports

void work_loop(void *data)
{
	int fd_max = wmedium.ctrlsock;

	fd_set read_fds;
	fd_set master;

	FD_ZERO(&master);
	FD_SET(wmedium.ctrlsock, &master);

	while (1) {
		int sresult = -EINVAL;

		FD_ZERO(&read_fds);
		read_fds = master;

		sresult = select((fd_max + 1), &read_fds, NULL, NULL, NULL);
		if (sresult > 0) {
			int nc = 0;
			for (nc = 0; nc < WIFIMEDIUM_MAX_PORTS; nc++) {
				if (hubport[nc].clisock > NO_SOCKET && FD_ISSET(hubport[nc].clisock, &read_fds)) {
					int nbytes = recv(hubport[nc].clisock, &(hubport[nc].rcvbuf), sizeof(struct wifi_iov), 0);
					if (nbytes) {	//TODO nbytes >= sizeof(struct ctrl_iov)
						if (hubport[nc].rcvbuf.__iov.mode) {	//wifi packet, broadcast
							int cnt = 0;
							for (cnt = 0; cnt < WIFIMEDIUM_MAX_PORTS; cnt++) {
								//broadcast
								if (cnt == nc || hubport[cnt].clisock == NO_SOCKET)
									continue;

								printf("XXX send to port %d\n", cnt);
								send(hubport[cnt].clisock, &(hubport[nc].rcvbuf), nbytes, 0);
							}
						} else /*if (!hubport[nc].rcvbuf.__iov.mode)*/ {	//port request
							if (hubport[nc].rcvbuf.__iov.hubid == wmedium.hub.hubid) {
								hubport[nc].rcvbuf.__iov.portid = hubport[nc].portid;
								printf("XXX new port requested %d\n", hubport[nc].portid);
								send(hubport[nc].clisock, &(hubport[nc].rcvbuf), sizeof(struct ctrl_iov), 0);
							} else {
								//send closing message to qemu client!!
								hubport[nc].rcvbuf.__iov.portid = -1;
								send(hubport[nc].clisock, &(hubport[nc].rcvbuf), sizeof(struct ctrl_iov), 0);
								close(hubport[nc].clisock);
								hubport[nc].clisock = NO_SOCKET;
								wmedium.hub.num_ports--;
							}
						}
					}
				}
			}

			if (FD_ISSET(wmedium.ctrlsock, &read_fds)) {
				int newfd = accept(wmedium.ctrlsock, NULL, NULL);
				if (newfd >= 0) {
					if (wmedium.hub.num_ports < WIFIMEDIUM_MAX_PORTS) {
						int i = 0;
						for (i = 0; i < WIFIMEDIUM_MAX_PORTS; i++) {
							if (hubport[i].clisock == NO_SOCKET) {
								hubport[i].clisock = newfd;
								hubport[i].portid = i;	//NOTE: for dynamic list portid makes sense
								wmedium.hub.num_ports++;

								fd_max = fd_max > newfd ? fd_max : newfd;
								FD_SET(newfd, &master);

								syslog(LOG_ERR, "new connection port @: %d\n", i);

								break;
							}
						}
					} else {
						//too many ports
						close(newfd);
					}
				}
			}

		} else {
			perror("select failure\n");
		}
	}
}

const char *const help_msg = 
	"wifimedium options as follows,\n"
	"\t\t-i XX,		terminal id to wich qemu backend driver connects\n"
	"\t\t-d,		daemon mode\n"
	"\t\t-l file-name,	log file name\n";

int main (int argc, char **argv)
{
	int i = 0;
	unsigned int tid = 20;
	char path[64] = { 0 };

	bzero(&wmedium, sizeof(struct wifimedium_global));
	for ( i = 0; i < WIFIMEDIUM_MAX_PORTS; i++) {
		wmedium.hub.ports[i].clisock = NO_SOCKET;
	}

	sprintf(path, WIFIMEDIUM_SERVER_SOCK, tid);

	//set up ctrl server socket
	wmedium.ctrlsock = __create_server_socket(path);
	if (wmedium.ctrlsock < 0) {
		printf("Socket Error: %d\n", errno);
		exit(EXIT_FAILURE);
	}
	wmedium.hub.hubid = tid;

	//select() and check all fds
	work_loop(&wmedium);

	return EXIT_SUCCESS;
}
