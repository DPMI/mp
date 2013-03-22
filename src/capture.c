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
		write_head* whead   = (write_head*)raw_buffer;
		cap_head* head      = whead->cp;
		unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

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

void destination_init(struct destination* dst, int index, unsigned char* buffer){
	dst->stream = NULL;
	dst->index = index;
	dst->state = IDLE;

	dst->ethhead=(struct ethhdr*)buffer; // pointer to ethernet header.
	dst->ethhead->h_proto=htons(ETHERTYPE_MP);    // Set the protocol field of the ethernet header.

	/* set the ethernet source address to adress used by the MA iface. */
	memcpy(dst->ethhead->h_source, &MPinfo->hwaddr, ETH_ALEN);

	dst->shead=(struct sendhead*)(buffer+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol
	dst->shead->sequencenr=htons(0x0000);                        // Initialize the sequencenr to zero.
	dst->shead->nopkts=htons(0);                                 // Initialize the number of packet to zero
	dst->shead->flags=htonl(0);                                  // Initialize the flush indicator.
	dst->shead->version.major=htons(CAPUTILS_VERSION_MAJOR);     // Specify the file format used, major number
	dst->shead->version.minor=htons(CAPUTILS_VERSION_MINOR);     // Specify the file format used, minor number

	dst->sendpointer=buffer+sizeof(struct ethhdr)+sizeof(struct sendhead);            // Set sendpointer to first place in sendmem where the packets will be stored.
	dst->sendptrref=dst->sendpointer;          // Grab a copy of the pointer, simplifies treatment when we sent the packets.
	dst->sendcount=0;                        // Initialize the number of pkt stored in the packet, used to determine when to send the packet.
}

void destination_init_all(){
	for( int i = 0; i < MAX_FILTERS; i++) {
		destination_init(&MAsd[i], i, sendmem[i]);
	}
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
