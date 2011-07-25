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
#include "sender.h"
#include "log.h"
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SEMAPHORE_TIMEOUT_SEC 1

static void flushBuffer(int i); // Flush sender buffer i.
static void flushAll(); /* flushes all send buffers */
void thread_init_finished(struct thread_data* td, int status);

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

int wait_for_capture(sem_t* sem){
  struct timespec ts;

  if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
    int saved = errno;
    fprintf(stderr, "clock_gettime() returned %d: %s\n", saved, strerror(saved));
    return saved;
  }

  ts.tv_sec += SEMAPHORE_TIMEOUT_SEC;
  
  if ( sem_timedwait(sem, &ts) != 0 ){
    int saved = errno;
    switch ( saved ){
    case ETIMEDOUT:
    case EINTR:
      break;
    default:
      fprintf(stderr, "sem_timedwait() returned %d: %s\n", saved, strerror(saved));
    }
    return saved;
  }
  
  return 0;
}

void send_packet(struct consumer* con){
  const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
  const size_t payload_size = con->sendpointer - con->sendptrref;
  const size_t packet_full_size = header_size + payload_size; /* includes ethernet, sendheader and payload */
  const uint32_t seqnr = ntohl(con->shead->sequencenr);

  con->shead->nopkts = htons(con->sendcount); //maSendsize;
  /*con->shead->losscounter=htons((globalDropcount+memDropcount)-dropCount[whead->consumer]); */
  con->dropCount = globalDropcount + memDropcount;

  {
    const u_char* data = con->sendptrref;
    size_t data_size = payload_size;
    
    if ( con->want_sendhead ){
      data -= header_size;
      data_size += header_size;
    }
    
    con->stream->write(con->stream, data, data_size);
  }

  fprintf(verbose, "SendThread [id:%u] sending %zd bytes\n", thread_id(), payload_size);
  fprintf(verbose, "\tcaputils-%d.%d\n", ntohs(con->shead->version.major), ntohs(con->shead->version.minor));
  fprintf(verbose, "\tdropCount[] = %d (g%d/m%d)\n", con->dropCount, globalDropcount, memDropcount);
  fprintf(verbose, "\tPacket length = %zd bytes, Eth %zd, Send %zd, Cap %zd bytes\n", packet_full_size, sizeof(struct ethhdr), sizeof(struct sendhead), sizeof(struct cap_header));
  fprintf(verbose, "\tSeqnr  = %04lx \t nopkts = %04x \t Losscount = %d\n", (unsigned long int)seqnr, ntohs(con->shead->nopkts), -1);
  
  //Update the sequence number.
  con->shead->sequencenr = htonl((seqnr+1) % 0xFFFF);

  /* update stats */
  MPstats->written_count += con->sendcount;
  MPstats->sent_count++;

  con->sendcount = 0;// Clear the number of packets in this sendbuffer
  bzero(con->sendptrref,(maSendsize*(sizeof(cap_head)+PKT_CAPSIZE))); //Clear the memory location, for the packet data. 
  con->sendpointer=con->sendptrref; // Restore the pointer to the first spot where the next packet will be placed.
}

static int can_defer_send(struct consumer* con, struct timespec* now, struct timespec* last_sent, int nextPDUlen){
  /* calculate time since last send. If it was long ago (longer than
   * MAX_PACKET_AGE) the send buffer is flushed even if it doesn't contain
   * enough payload for a full packet. */
  signed long int sec = (now->tv_sec - last_sent->tv_sec) * 1000;
  signed long int msec = (now->tv_nsec - last_sent->tv_nsec);
  msec /= 1000000; /* please keep this division a separate statement. It ensures
		    * that the subtraction above is stored as a signed value. If
		    * the division is put together the subtraction will be
		    * calculated as unsigned (tv_psec is stored as unsigned),
		    * then divided and only then  converted to signed int. */

  const signed long int age = sec + msec;
  const size_t payload_size = con->sendpointer - con->sendptrref;
  const size_t mtu_size = MPinfo->MTU -2*(sizeof(cap_head)+nextPDUlen); // This row accounts for the fact that the consumer buffers only need extra space for one PDU of of the capture size for that particular filter. 


  const int larger_mtu = payload_size >= mtu_size;
  const int need_flush = con->status == 0 && payload_size > 0;
  const int old_age = age >= MAX_PACKET_AGE;

  return  !( old_age || larger_mtu || need_flush );
}

static int oldest_packet(int nics, int readPos[], sem_t* semaphore){
  int oldest = -1;
  while( oldest == -1 ){       // Loop while we havent gotten any pkts.
    if ( terminateThreads>0 ) {
      return -1;
    }

    struct picotime timeOldest;        // timestamp of oldest packet
    timeOldest.tv_sec = UINT32_MAX;
    timeOldest.tv_psec = UINT64_MAX;
    
    for( int i = 0; i < nics; i++){
      unsigned char* raw_buffer = datamem[i][readPos[i]];
      write_head* whead   = (write_head*)raw_buffer;
      cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
      
      /* This consumer has no packages yet */
      if( whead->free == 0 ) {
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
      wait_for_capture(semaphore);
    }
  }

  return oldest;
}

void copy_to_sendbuffer(struct consumer* dst, unsigned char* src, int* readPtr, struct CI* CI){
  int readPos = *readPtr;

  write_head* whead   = (write_head*)src;
  cap_head* head      = (cap_head*)(src + sizeof(write_head));
  const size_t packet_size = sizeof(cap_head)+head->caplen;

  assert(dst);
  assert(readPtr);
  assert(CI);
  assert(CI->buffer_usage > 0);

  pthread_mutex_lock(&CI->mutex);
  {
    /* mark as free */
    assert(whead->free > 0);
    whead->free = 0;
    CI->buffer_usage--;
    
    /* copy packet */
    memcpy(dst->sendpointer, head, packet_size);
    memset(head, 0, sizeof(cap_head) + PKT_CAPSIZE);
  }
  pthread_mutex_unlock(&CI->mutex);

  /* increment read position */
  *readPtr = (readPos+1) % PKT_BUFFER ;
  
  /* update sendpointer */
  dst->sendpointer += packet_size;
  dst->sendcount += 1;
}

void* sender_capfile(struct thread_data* td, void* ptr){
  send_proc_t* proc = (send_proc_t*)ptr;
  int readPos[CI_NIC] = {0,};        /* read pointers */

  logmsg(stderr, "Sender initializing (local mode).\n");
 
  long int ret;

  struct consumer con;
  consumer_init(&con, 0, sendmem[0]); /* in local mode only 1 stream is created, so it is safe to "steal" memory from consumer 0 */
  con.want_sendhead = 0;

  if ( (ret=createstream(&con.stream, proc->filename, PROTOCOL_LOCAL_FILE, NULL, mampid_get(MPinfo->id), MPinfo->comment)) != 0 ){
    logmsg(stderr, "  createstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
    sem_post(proc->semaphore); /* unlock main thread */
    return NULL;
  }

  /* unlock main thread */
  thread_init_finished(td, 0);

  while( terminateThreads == 0 ){
    int oldest = oldest_packet(proc->nics, readPos, proc->semaphore);
    
    /* couldn't find a packet, gave up waiting. we are probably terminating. */
    if ( oldest == -1 ){
      continue;
    }
    
    unsigned char* raw_buffer = datamem[oldest][readPos[oldest]];

    copy_to_sendbuffer(&con, raw_buffer, &readPos[oldest], &_CI[oldest]);    
    send_packet(&con);
  }

  logmsg(stderr, "Sender finished (local).\n");
  return NULL;
}

void* sender_caputils(struct thread_data* td, void *ptr){
    send_proc_t* proc = (send_proc_t*)ptr;      // Extract the parameters that we got from our master, i.e. parent process..
    const int nics = proc->nics;             // The number of active CIs

    int readPos[CI_NIC] = {0,};        // array of memory positions
    int nextPDUlen=0;                  // The length of PDUs stored in the selected consumer.

    logmsg(stderr, "Sender initializing. There are %d captures.\n", nics);

    /* Timestamp when the sender last sent a packet.  */
    struct timespec last_sent;
    clock_gettime(CLOCK_REALTIME, &last_sent);

    /* unlock main thread */
    thread_init_finished(td, 0);

    /* sender loop */
    while( terminateThreads == 0 ){
      int oldest = oldest_packet(proc->nics, readPos, proc->semaphore);
      
      /* couldn't find a packet, gave up waiting. we are probably terminating. */
      if ( oldest == -1 ){
	continue;
      }

      unsigned char* raw_buffer = datamem[oldest][readPos[oldest]];
      write_head* whead   = (write_head*)raw_buffer;
      cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
      struct consumer* con = &MAsd[whead->consumer];

      copy_to_sendbuffer(con, raw_buffer, &readPos[oldest], &_CI[oldest]);
      nextPDUlen = head->caplen;

      /* get current timestamp */
      struct timespec now;
      clock_gettime(CLOCK_REALTIME, &now);

      if ( can_defer_send(con, &now, &last_sent, nextPDUlen) ){
	continue;
      }

      /* send packet */
      send_packet(con);

      /* store timestamp (used to determine if sender must be flushed or not, due to old packages) */
      last_sent = now;
    }

    logmsg(verbose, "Flushing sendbuffers.\n");
    flushAll();

    printf("Sender Child %ld My work here is done .\n", pthread_self());
    return(NULL) ;
}

static void flushBuffer(int i){
  struct consumer* con = &MAsd[i];
  
  /* no consumer */
  if ( !con || con->status == 0 ){
    return;
  }

  /* nothing to flush */
  if ( con->sendcount == 0 ){
    return;
  }

  logmsg(stderr, "Consumer %d needs to be flushed, contains %d pkts\n", i, con->sendcount);

  con->shead->flush=htons(1);
  send_packet(con);
  con->shead->flush=htons(0);
}

static void flushAll(){
  for( int i = 0; i < CONSUMERS; i++){
    flushBuffer(i);
  }
}
