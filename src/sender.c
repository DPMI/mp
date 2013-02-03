/***************************************************************************
                          sender.c  -  description
                             -------------------
    begin                : Sat Mar 15 2003
    copyright            : (C) 2003-2005 by Patrik Arlos
    email                : patrik.arlos@bth.se
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
  This thread recives a semaphore from the capture threads and starts reading
  the shared memory in order by timestamps. The packets read from the memory
  are appended together into tcp packets and sent to the tcpserver software.
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "destination.h"
#include "sender.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SEMAPHORE_TIMEOUT_SEC 1

static void flushBuffer(int i, int terminate); // Flush sender buffer i.
static void flushAll(int terminate); /* flushes all send buffers */
void thread_init_finished(struct thread_data* td, int status);

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

int wait_for_capture(sem_t* sem){
	struct timespec ts;

	if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
		int saved = errno;
		logmsg(stderr, SENDER, "clock_gettime() returned %d: %s\n", saved, strerror(saved));
		return saved;
	}

	ts.tv_sec += SEMAPHORE_TIMEOUT_SEC;

	int ret;
	if ( (ret=sem_timedwait(sem, &ts)) != 0 ){
		const int saved = errno;
		switch ( saved ){
		case ETIMEDOUT:
		case EINTR:
			break;
		default:
			logmsg(stderr, SENDER, "sem_timedwait(%p) returned %d: %s\n", sem, ret, strerror(saved));
		}
		return saved;
	}

	return 0;
}

void send_packet(struct destination* dst){
	const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
	const size_t payload_size = dst->sendpointer - dst->sendptrref;
	const size_t packet_full_size = header_size + payload_size; /* includes ethernet, sendheader and payload */
	const uint32_t seqnr = ntohl(dst->shead->sequencenr);

	assert(payload_size > 0);

	dst->shead->flags  = htonl(dst->shead->flags);
	dst->shead->nopkts = htonl(dst->sendcount);

	int ret;

	const u_char* data = dst->sendptrref;
	size_t data_size = payload_size;

	if ( dst->want_ethhead ){
		data -= header_size;
		data_size += header_size;
	} else if ( dst->want_sendhead ){
		data -= sizeof(struct sendhead);
		data_size += sizeof(struct sendhead);
	}

	ret = stream_write(dst->stream, data, data_size);

	logmsg(verbose, SENDER, "Filter %d sending %zd bytes with %d packets\n", dst->filter->filter_id, data_size, ntohl(dst->shead->nopkts));
	if ( debug_flag ){
		if ( ret == 0 ){
			logmsg(verbose, SENDER, "\tcaputils-%d.%d\n", ntohs(dst->shead->version.major), ntohs(dst->shead->version.minor));
			logmsg(verbose, SENDER, "\tdst: %s\n", stream_addr_ntoa(&dst->filter->dest));
			logmsg(verbose, SENDER, "\tPacket length = %zd bytes, Eth %zd, Send %zd, Cap %zd bytes\n", packet_full_size, sizeof(struct ethhdr), sizeof(struct sendhead), sizeof(struct cap_header));
			logmsg(verbose, SENDER, "\tSeqnr  = %04lx \t nopkts = %04d\n", (unsigned long int)seqnr, ntohl(dst->shead->nopkts));
		} else {
			logmsg(stderr,  SENDER, "\tstream_write() returned %d: %s\n", ret, strerror(ret));
			logmsg(verbose, SENDER, "\tPacket length = %zd bytes, Eth %zd, Send %zd, Cap %zd bytes\n", packet_full_size, sizeof(struct ethhdr), sizeof(struct sendhead), sizeof(struct cap_header));
		}
	}

	//Update the sequence number and reset
	dst->shead->sequencenr = htonl((seqnr+1) % 0xFFFF);
	dst->shead->flags = 0;

	/* update stats */
	MPstats->written_count += dst->sendcount;
	MPstats->sent_count++;

	dst->sendcount = 0;                  // Clear the number of packets in this sendbuffer
	dst->sendpointer = dst->sendptrref;  // Restore the pointer to the first spot where the next packet will be placed.
}

static int oldest_packet(int nics, sem_t* semaphore){
	int oldest = -1;
	while( oldest == -1 ){       // Loop while we havent gotten any pkts.
		if ( terminateThreads>0 ) {
			return -1;
		}

		struct picotime timeOldest;        // timestamp of oldest packet
		timeOldest.tv_sec = UINT32_MAX;
		timeOldest.tv_psec = UINT64_MAX;

		for( int i = 0; i < nics; i++){
			const int readpos = _CI[i].readpos;
			unsigned char* raw_buffer = datamem[i][readpos];
			const struct write_header* whead = (write_head*)raw_buffer;
			const struct cap_header* head = whead->cp;

			/* This destination has no packages yet */
			if( whead->used == 0 ) {
				continue;
			}

			if( timecmp(&head->ts, &timeOldest) < 0 ){
				timeOldest.tv_sec  = head->ts.tv_sec;
				timeOldest.tv_psec = head->ts.tv_psec;
				oldest = i;
			}
		}

		/* No packages, wait until some arrives */
		if ( oldest==-1 ){
			int ret = wait_for_capture(semaphore);
			if ( ret == ETIMEDOUT ){
				return -2;
			}
		}
	}

	return oldest;
}

void copy_to_sendbuffer(struct destination* dst, struct write_header* whead, struct CI* CI){
	const struct cap_header* head = whead->cp;
	const size_t packet_size = sizeof(cap_head) + head->caplen;

	assert(dst);
	assert(CI);
	assert(whead->used);

	/* increment read position */
	CI->readpos = (CI->readpos+1) % PKT_BUFFER;

	/* copy packet */
	memcpy(dst->sendpointer, head, packet_size);

	/* mark as free */
	whead->used = 0;

	/* update sendpointer */
	dst->sendpointer += packet_size;
	dst->sendcount += 1;
}

void* sender_capfile(struct thread_data* td, void* ptr){
	send_proc_t* proc = (send_proc_t*)ptr;

	logmsg(stderr, SENDER, "Initializing (local mode).\n");

	struct destination dst;
	destination_init(&dst, 0, sendmem[0]); /* in local mode only 1 stream is created, so it is safe to "steal" memory from destination 0 */
	dst.want_ethhead = 0;
	dst.want_sendhead = 0;

	//if ( (ret=createstream(&con.stream, &dest, NULL, mampid_get(MPinfo->id), MPinfo->comment)) != 0 ){
	//  logmsg(stderr, SENDER, "  createstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
	//      sem_post(proc->semaphore); /* unlock main thread */
	//  return NULL;
	//}

	/* unlock main thread */
	thread_init_finished(td, 0);

	while( terminateThreads == 0 ){
		int oldest = oldest_packet(proc->nics, proc->semaphore);

		/* couldn't find a packet, gave up waiting. we are probably terminating. */
		if ( oldest == -1 ){
			continue;
		}

		struct CI* CI = &_CI[oldest];
		unsigned char* raw_buffer = datamem[oldest][CI->readpos];
		struct write_header* whead = (write_head*)raw_buffer;

		copy_to_sendbuffer(&dst, whead, CI);
		send_packet(&dst);
	}

	logmsg(stderr, SENDER, "Finished (local).\n");
	return NULL;
}

static void flush_senders(){
	/* get current timestamp */
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);

	for ( int i = 0; i < MAX_FILTERS; i++ ){
		struct destination* dst = &MAsd[i];
		const size_t payload_size = dst->sendpointer - dst->sendptrref;

		if ( payload_size > 0 ){
			const int need_flush = dst->state != BUSY && payload_size > 0;

			/* calculate time since last send. If it was long ago (longer than
			 * MAX_PACKET_AGE) the send buffer is flushed even if it doesn't contain
			 * enough payload for a full packet. */
			signed long int sec = (now.tv_sec - dst->last_sent.tv_sec) * 1000;
			signed long int msec = (now.tv_nsec - dst->last_sent.tv_nsec);
			msec /= 1000000; /* please keep this division a separate statement. It ensures
			                  * that the subtraction above is stored as a signed value. If
			                  * the division is put together the subtraction will be
			                  * calculated as unsigned (tv_psec is stored as unsigned),
			                  * then divided and only then  converted to signed int. */
			const signed long int age = sec + msec;
			const int old_age = age >= MAX_PACKET_AGE;

			if ( need_flush || old_age ){
				send_packet(dst);
				dst->last_sent = now;
			}
		}

		/* stop destinations flagged for termination */
		if ( dst->state == STOP ){
			int ret;
			logmsg(verbose, SENDER, "Closing stream %d\n", dst->index);
			if ( (ret=stream_close(dst->stream)) != 0 ){
				logmsg(stderr, SENDER, "stream_close() returned 0x%08x: %s\n", ret, caputils_error_string(ret));
			}
			dst->stream = NULL;
			dst->state = IDLE;
		}
	}
}

static void fill_senders(const send_proc_t* proc){
	static const size_t header_size = sizeof(struct ethhdr) + sizeof(struct cap_header) + sizeof(struct sendhead);

	const int oldest = oldest_packet(proc->nics, proc->semaphore);

	/* couldn't find a packet, gave up waiting. we are probably terminating. */
	if ( oldest == -1 ){
		return;
	}

	/* timeout, flush all buffers */
	if( oldest == -2 ){
		flushAll(0);
		return;
	}

	struct CI* CI = &_CI[oldest];
	unsigned char* raw_buffer  = datamem[oldest][CI->readpos];
	struct write_header* whead = (write_head*)raw_buffer;
	struct cap_header* head    = whead->cp;
	struct destination* dst    = &MAsd[whead->destination];

	/* calculate size of sendbuffer and compare with MTU */
	const size_t payload_size = dst->sendpointer - dst->sendptrref;
	const int larger_mtu = payload_size + head->caplen + header_size > MPinfo->MTU;

	/* if the current packet doesn't fit flush first */
	if ( larger_mtu ){
		assert(payload_size > 0 && dst->sendcount > 0 && "packet didn't fit into frame but frame is empty");
		send_packet(dst);
	}

	/* copy packet into buffer */
	copy_to_sendbuffer(dst, whead, CI);
}

void* sender_caputils(struct thread_data* td, void *ptr){
	send_proc_t* proc = (send_proc_t*)ptr;    /* Extract the parameters that we got from our master, i.e. parent process.. */
	const int nics = proc->nics;              /* The number of active CIs */

	logmsg(stderr, SENDER, "Initializing. There are %d captures.\n", nics);

	/* initialize timestamp */
	{
		struct timespec tmp;
		clock_gettime(CLOCK_REALTIME, &tmp);
		for ( int i = 0; i < MAX_FILTERS; i++ ){
			MAsd[i].last_sent = tmp;
		}
	}

	/* unlock main thread */
	thread_init_finished(td, 0);

	/* sender loop */
	while( terminateThreads == 0 ){
		flush_senders();
		fill_senders(proc);
	}

	logmsg(verbose, SENDER, "Flushing sendbuffers.\n");
	flushAll(1);

	logmsg(stderr, SENDER, "Finished.\n");
	return(NULL) ;
}

/**
 * Forces a flush of the sendbuffer.
 * @param i Filter index.
 * @param terminate If non-zero it instructs the consumers that the MP is
 *                  terminating.
 */
static void flushBuffer(int i, int terminate){
	struct destination* dst = &MAsd[i];

	/* no destination */
	if ( !dst || dst->state == IDLE ){
		return;
	}

	/* nothing to flush */
	if ( dst->sendcount == 0 ){
		return;
	}

	logmsg(stderr, SENDER, "Destination %d needs to be flushed, contains %d pkts (%zd bytes)\n", i, dst->sendcount, dst->sendpointer - dst->sendptrref);

	dst->shead->flags = SENDER_FLUSH;
	send_packet(dst);
}

static void flushAll(int terminate){
	for( int i = 0; i < MAX_FILTERS; i++){
		flushBuffer(i, terminate);
	}
}
