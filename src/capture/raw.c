#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define BUFFER_SIZE 4096

struct raw_context {
	struct capture_context base;
	int socket;
	char buffer[BUFFER_SIZE];
};

//Sets Nic to promisc mode
static void setpromisc(int sd, char* device)
{
	struct ifreq	ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if(ioctl(sd, SIOCGIFFLAGS, &ifr)==-1)
		{
			printf("can't open flags");
			exit(1);
		}
	if (ifr.ifr_flags & IFF_PROMISC)
		{
			return;
		}
	else
		{
			ifr.ifr_flags |= IFF_PROMISC;
			if(ioctl(sd, SIOCSIFFLAGS, &ifr)==-1)
				{
					printf("can't enter promisc");
					return;
				}
		}
	return;
}

/**
 * Get the right id for nic (ethX->interface index) Used for bind
 * @return ID or -1 on errors (errno is raised)
 */
static int iface_get_id(int sd, const char *device) {
	struct ifreq	ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		return -1;
	}

	return ifr.ifr_ifindex;
}

//Bind socket to Interface
static int iface_bind(int fd, int ifindex){
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= PF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		fprintf(stderr, "bind: %d: %s", errno, strerror(errno));
		return -1;
	}
	return 0;
}

static int read_packet_raw(struct raw_context* ctx, unsigned char* dst, struct cap_header* head){
	int sd = ctx->socket;
	struct timeval timeout = {1, 0};

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(sd, &fds);

	/* wait until data is available on socket */
	if ( select(sd+1, &fds, NULL, NULL, &timeout) == -1 ){
		switch ( errno ){
		case EAGAIN:
		case EINTR:
			return 0;

		default:
			logmsg(stderr, CAPTURE, "select() failed with code %d: %s\n", errno, strerror(errno));
			return -1;
		}
	}

	/* read from socket */
	const ssize_t bytes = recvfrom(sd, ctx->buffer, BUFFER_SIZE, MSG_TRUNC, NULL, NULL);

	/* check errors */
	if ( bytes == -1 ){
		if ( errno == EAGAIN ){
			return 0;
		}
		int save = errno;
		logmsg(stderr, CAPTURE, "recvfrom() failed with code %d: %s\n", save, strerror(save));
		errno = save;
		return -1;
	}

	/* grab timestamp */
	struct timeval tv;
	ioctl(sd, SIOCGSTAMP, &tv );

	const size_t data_len = MIN(bytes, PKT_CAPSIZE);
	const size_t padding = PKT_CAPSIZE - data_len;

	memcpy(dst, ctx->buffer, data_len);
	memset(dst + data_len, 0, padding);

	head->ts.tv_sec   = tv.tv_sec;            // Store arrival time in seconds
	head->ts.tv_psec  = tv.tv_usec * 1000000; // Write timestamp in picosec
	head->len         = bytes;
	head->caplen      = data_len;

	return data_len;
}

int stats(struct raw_context* ctx){
	struct tpacket_stats kstats;
	socklen_t len = sizeof (struct tpacket_stats);

	if ( getsockopt(ctx->socket, SOL_PACKET, PACKET_STATISTICS, &kstats, &len) != 0 ) {
		logmsg(stderr, CAPTURE, "failed to read stats for %s: %s\n", ctx->base.iface, strerror(errno));
		return 1;
	}

	logmsg(stderr, CAPTURE, "  %d packets received by filter\n", kstats.tp_packets);
	logmsg(stderr, CAPTURE, "  %d packets dropped by kernel\n", kstats.tp_drops);
	return 0;
}

/* This is the RAW_SOCKET capturer..   */
void* capture(void* ptr){
	struct CI* CI = (struct CI*)ptr;
	struct raw_context cap;
	cap.base.iface = CI->iface;

	/* initialize raw capture */
	logmsg(verbose, CAPTURE, "CI[%d] initializing capture on %s using RAW_SOCKET (memory at %p).\n", CI->id, cap.base.iface, &datamem[CI->id]);

	/* open socket */
	CI->sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	cap.socket = CI->sd;

	/* setup socket properties */
	int ifindex = iface_get_id(CI->sd, CI->iface);
	iface_bind(CI->sd, ifindex);
	setpromisc(CI->sd, CI->iface);

	/* setup callbacks */
	cap.base.init = 0;
	cap.base.destroy = 0;
	cap.base.read_packet = (read_packet_callback)read_packet_raw;
	cap.base.stats = (stats_callback)stats;

	/* start capture */
	capture_loop(CI, (struct capture_context*)&cap);
	return NULL;
}
