#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <assert.h>

static const int pcap_timeout = 500;

struct pcap_context {
	struct capture_context base;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
};

static int read_packet_pcap(struct pcap_context* ctx, unsigned char* dst, struct cap_header* head){
	struct pcap_pkthdr* pcaphead;
	const u_char* payload;

	switch ( pcap_next_ex(ctx->handle, &pcaphead, &payload) ){
	case 1: /* ok */
		break;

	case 0: /* timeout */
		return 0;

	case -2: /* offline capture EOF */
		logmsg(verbose, CAPTURE, "pcap offline capture EOF\n");
		return -1;

	case -1: /* error */
		logmsg(stderr, CAPTURE, "pcap_next(): %s\n", pcap_geterr(ctx->handle));
		return -1;
	}

	assert(pcaphead->caplen <= snaplen());
	memcpy(dst, payload, pcaphead->caplen);

	head->ts.tv_sec   = pcaphead->ts.tv_sec;            // Store arrival time in seconds
	head->ts.tv_psec  = pcaphead->ts.tv_usec * 1000000; // Write timestamp in picosec
	head->len         = pcaphead->len;
	head->caplen      = pcaphead->caplen;
	/*head->flags       = 0;*/

	return pcaphead->caplen;
}

static void init_live(struct pcap_context* cap){
	logmsg(verbose, CAPTURE, "  pcap live capture (timeout: %dms)\n", pcap_timeout);
	cap->handle = pcap_open_live (cap->base.iface, snaplen(), 1, pcap_timeout, cap->errbuf);   /* open device for reading */
}

static void init_offline(struct pcap_context* cap){
	cap->base.iface = cap->base.iface + 1; /* +1 to remove : */
	logmsg(verbose, CAPTURE, "  pcap offline capture\n");
	cap->handle = pcap_open_offline (cap->base.iface, cap->errbuf);
}

static int init(struct pcap_context* cap){
	/* reset error message, mostly to make sure valgrind is silent */
	memset(cap->errbuf, 0, PCAP_ERRBUF_SIZE);

	if ( cap->base.iface[0] != ':' ){ /* live capture */
		init_live(cap);
	} else { /* offline capture */
		init_offline(cap);
	}

	if ( !cap->handle ) {
		logmsg(stderr, CAPTURE, "pcap_open: %s\n", cap->errbuf);
		return EINVAL;
	}

	return 0;
}

static int destroy(struct pcap_context* cap){
	pcap_close(cap->handle);
	return 0;
}

static int stats(struct pcap_context* cap){
	struct pcap_stat ps;
	pcap_stats(cap->handle, &ps);

	logmsg(stderr, CAPTURE, "  %d packets received by filter\n", ps.ps_recv);
	logmsg(stderr, CAPTURE, "  %d packets dropped by pcap (full buffers)\n", ps.ps_drop);
	logmsg(stderr, CAPTURE, "  %d packets dropped by kernel\n", ps.ps_ifdrop);

	return 0;
}

/* This is the PCAP_SOCKET capturer..   */
void* pcap_capture(void* ptr){
	struct CI* CI = (struct CI*)ptr;
	struct pcap_context cap;
	capture_init(&cap.base, CI->iface);

	logmsg(verbose, CAPTURE, "CI[%d] initializing capture on %s using pcap (memory at %p).\n", CI->id, cap.base.iface, CI->buffer);

	/* setup callbacks */
	cap.base.init = (init_callback)init;
	cap.base.destroy = (destroy_callback)destroy;
	cap.base.read_packet = (read_packet_callback)read_packet_pcap;
	cap.base.stats = (stats_callback)stats;

	/* start capture */
	capture_loop(CI, (struct capture_context*)&cap);

	/* stop capture */
	logmsg(verbose, CAPTURE, "CI[%d] stopping capture on %s.\n", CI->id, cap.base.iface);

	return NULL;
}
