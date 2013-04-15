/***************************************************************************
                          capture.c  -  description
                             -------------------
    begin                : Tue Nov 26 2002
    copyright            : (C) 2002 by Anders Ekberg
                           (C) 2002-2005 by Patrik Arlos (PAL)
                           (C) 2011 by David Sveningsson
    email                : anders.ekberg@bth.se
                           patrik.arlos@bth.se
                           rasmus.melgaard@bth.se
                           david.sveningsson@bth.se

    changelog
    2005-03-05           Merged in pcap version(RMA) of capture. (PAL)
    2008-04-02           Misc. changes, moving up to version 0.6
    2011-04-13           Major refactoring, bumping to 0.7

***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 This thread recives all packets on the network interface, timestamps them
 and put them in the shared memory for the sender thread to read.

***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture.h"
#include "log.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

extern int show_packets;
static struct CI CI[CI_NIC];
struct CI* _CI = CI;
static int tdflag = 0;          /* Number of T_delta definitions. */

u_char datamem[CI_NIC][PKT_BUFFER][(PKT_CAPSIZE+sizeof(write_head)+sizeof(cap_head))] = {{{0,}}};

static int push_packet(struct CI* CI, write_head* whead, cap_head* head, unsigned char* packet_buffer){
	const int recipient = filter(CI->iface, packet_buffer, head);
	if ( recipient == -1 ){ /* no match */
		return -1;
	}

	if ( __builtin_expect(show_packets, 0) ){
		logmsg(stderr, SENDER, "PKT ");
		format_pkg(stderr, &CI->format, head);
	}

	if ( __builtin_expect(whead->used, 0) ){ //Control buffer overrun
		if ( CI->seq_drop == 0){
			logmsg(stderr, CAPTURE, "CI[%d] Buffer full, dropping packet(s). writepos=%d, bufferUsage=%d\n", CI->id, CI->writepos, buffer_utilization(CI));
		}
		CI->dropped_count++;
		CI->seq_drop++;
		return -1;
	} else if ( __builtin_expect(CI->seq_drop > 1, 0) ){
		logmsg(stderr, CAPTURE, "CI[%d] .. %d packets was dropped.\n", CI->id, CI->seq_drop);
	}

	/* increment write position */
	CI->writepos = (CI->writepos+1) % PKT_BUFFER;
	CI->seq_drop = 0;

	whead->destination = recipient;  /* store recipient */
	whead->used = 1;                 /* marks the post that it has been written. This must always be the last action as the sender might kick in otherwise  */

	/* flag that another packet is ready */
	if ( sem_post(CI->semaphore) != 0 ){
		logmsg(stderr, CAPTURE, "sem_post() returned %d: %s\n", errno, strerror(errno));
	}

	return recipient;
}

static int fill_caphead(cap_head* head, const char* iface, const char* MAMPid){
	/* reset caphead to it won't contain any garbage */
	memset(head, 0, sizeof(cap_head));

	strncpy(head->nic, iface, 8);
	strncpy(head->mampid, MAMPid, 8);

	/* force nullterminator */
	head->mampid[7] = 0;
	return 0;
}

static void wait_for_auth(){
	while ( terminateThreads == 0 ){
		if ( MPinfo->id ){
			return;
		}
		sleep(1); /** @todo should use a pthread cond. variable */
	}
}

int add_capture(const char* iface){
	if ( noCI == CI_NIC ){
		logmsg(stderr, MAIN, "Cannot specify more than %d capture interface(s)\n", CI_NIC);
		return 0;
	}

	/* initialize driver */
	size_t t;
	CI[noCI].driver = ci_driver_from_iface(iface, &t);
	CI[noCI].iface = strdup(iface + t);

	/* initialize fields */
	CI[noCI].id = noCI;
	CI[noCI].sd = -1;
	CI[noCI].flag = NULL;
	CI[noCI].semaphore = NULL;
	CI[noCI].packet_count = 0;
	CI[noCI].matched_count = 0;
	CI[noCI].dropped_count = 0;
	CI[noCI].seq_drop = 0;
	CI[noCI].accuracy = 0;
	pthread_mutex_init(&CI[noCI].mutex, NULL);
	format_setup(&CI->format, FORMAT_DATE_STR | FORMAT_DATE_LOCALTIME | FORMAT_LAYER_APPLICATION);

	noCI++;
	return 1;
}

void set_td(const char* arg){
	CI[tdflag].accuracy = atoi(arg);
	tdflag++;
}


int setup_capture(sem_t* semaphore){
	int ret = 0;
	sem_t flag;

	logmsg(verbose, MAIN, "Creating capture_threads.\n");

	sem_init(&flag, 0, 0);

	/* reset memory */
	memset(datamem, 0, sizeof(datamem));

	/* launch all capture threads */
	for (int i=0; i < noCI; i++) {
		CI[i].semaphore = semaphore;
		CI[i].flag = &flag;

		const capture_func func = ci_get_function(CI[i].driver);
		if ( !func ) return EINVAL; /* error already shown */

		if ( (ret=pthread_create(&CI[i].thread, NULL, func, &CI[i])) != 0 ) {
			logmsg(stderr, MAIN, "Error creating capture thread.");
			return ret;
		}
	}

	/* await completion
	 * not using flag_wait because it should wait a total of N secs and not N secs
	 * per thread. */
	{
		struct timespec ts;
		if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
			int saved = errno;
			logmsg(stderr, MAIN, "clock_gettime() returned %d: %s\n", saved, strerror(saved));
			return saved;
		}
		ts.tv_sec += 20; /* 20s timeout */

		for (int i=0; i < noCI; i++) {
			if ( sem_timedwait(&flag, &ts) == 0 ){
				continue;
			}

			int saved = errno;
			switch ( saved ){
			case ETIMEDOUT:
			case EINTR:
				break;
			default:
				logmsg(stderr, MAIN, "sem_timedwait() returned %d: %s\n", saved, strerror(saved));
			}
			return saved;
		}
	}

	sem_destroy(&flag);
	return 0;
}

int capture_loop(struct CI* CI, struct capture_context* cap){
	int ret;

	/* initialize driver */
	if ( cap->init && (ret=cap->init(cap)) != 0 ){
		sem_post(CI->flag); /* unlock parent */
		return ret; /* return error */
	}

	/* flag that thread is ready for capture */
	sem_post(CI->flag);

	/* wait until the MP is authorized until it starts capture */
	wait_for_auth();

	CI->writepos = 0; /* Reset write-position in memory */
	while(terminateThreads==0){
		/* calculate pointers into writebuffer */
		unsigned char* raw_buffer = datamem[CI->id][CI->writepos];
		struct write_header* whead = (write_head*)raw_buffer;
		struct cap_header* head = whead->cp;
		unsigned char* packet_buffer = (unsigned char*)head->payload;

		/* fill details into capture header */
		fill_caphead(head, CI->iface, MPinfo->id);

		/* read a packet */
		ssize_t bytes = cap->read_packet(cap, packet_buffer, head);

		if ( bytes < 0 ){ /* failed to read */
			break;
		} else if ( bytes == 0 ){ /* no data */
			continue;
		}

		/* stats */
		CI->packet_count++;

		/* return -1 when no filter matches */
		if ( push_packet(CI, whead, head, packet_buffer) == -1 ){
			continue;
		}

		/* stats */
		CI->matched_count++;
	}

	/* stop capture */
	logmsg(verbose, CAPTURE, "CI[%d] stopping capture on %s.\n", CI->id, CI->iface);

	/* show stats */
	if ( cap->stats ){
		cap->stats(cap);
	}

	/* driver cleanup */
	if ( cap->destroy && (ret=cap->destroy(cap)) != 0 ){
		return ret; /* return error */
	}

	return 0;
}

int capture_init(struct capture_context* cap, const char* iface){
	memset(cap, 0, sizeof(struct capture_context));
	cap->iface = iface;
	return 0;
}

int buffer_utilization(struct CI* CI){
	const int r = CI->readpos;
	const int w = CI->writepos;

	if ( w >= r ){
		return w -r ;
	} else {
		return PKT_BUFFER - r + w;
	}
}

enum CIDriver ci_driver_from_iface(const char* iface, size_t* offset){
	size_t tmp;
	if ( !offset ){
		offset = &tmp;
	}

	*offset = 0;
	if ( strncmp("pcap", iface, 4) == 0 ){
		*offset = 4;
		return DRIVER_PCAP;
	} else if (strncmp("dag", iface, 3)==0) {
		return DRIVER_DAG;
	} else if (strncmp("raw", iface, 3)==0) {
		*offset = 3;
		return DRIVER_RAW;
	} else {
#ifdef HAVE_DRIVER_PCAP
		return DRIVER_PCAP;
#else
		return DRIVER_RAW;
#endif
	}
}

capture_func ci_get_function(enum CIDriver driver){
	switch ( driver ){
	case DRIVER_PCAP:
#ifdef HAVE_DRIVER_PCAP
		return pcap_capture;
#else /* HAVE_DRIVER_PCAP */
		logmsg(stderr, CAPTURE, "This MP lacks support for libpcap (rebuild with --with-pcap)\n");
		return NULL;
#endif /* HAVE_DRIVER_PCAP */
		break;

	case DRIVER_RAW:
#ifdef HAVE_DRIVER_RAW
		return capture;
#else
		logmsg(stderr, MAIN, "This MP lacks support for raw packet capture (use libpcap or DAG instead or rebuild with --with-raw)\n");
		return NULL;
#endif /* HAVE_DRIVER_RAW */
		break;

	case DRIVER_DAG:
#ifdef HAVE_DAG
#ifdef HAVE_DRIVER_DAG
		return dag_capture;
#else /* HAVE_DRIVER_DAG */
		return dag_legacy_capture;
#endif
#else /* HAVE_DAG */
		logmsg(stderr, MAIN, "This MP lacks support for Endace DAG (rebuild with --with-dag)\n");
		return NULL;
#endif
		break;

	default:
		abort(); /* cannot happen, defaults to PCAP or RAW */
		break;
	}
}
