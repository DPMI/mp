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

#include "capture.h"
#include "log.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>

extern int counter;
extern char* ebuf;
extern void* dagbuf[];
extern int dagfd[];
extern int skipflag;

pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

static int push_packet(struct CI* CI, write_head* whead, cap_head* head, const unsigned char* packet_buffer){
  const int recipient = filter(CI->nic, packet_buffer, head);
  if ( recipient == -1 ){ /* no match */
    return -1;
  }
  
  // prevent the reader from operating on the same chunk of memory.
  pthread_mutex_lock( &mutex2 );
  {
    strncpy(head->nic, CI->nic, 8); head->nic[7] = 0;
    strncpy(head->mampid, MAMPid, 8); head->mampid[7] = 0;
    whead->free++; //marks the post that it has been written
    whead->consumer = recipient;
  }
  pthread_mutex_unlock( &mutex2 );
  
  if ( whead->free>1 ){ //Control buffer overrun
    logmsg(stderr, "CI[%d] OVERWRITING: %ld @ %d for the %d time \n", CI->id, pthread_self(), CI->writepos, whead->free);
    logmsg(stderr, "CI[%d] bufferUsage=%d\n", CI->id, CI->bufferUsage);
  }

  CI->writepos++;
  CI->bufferUsage++;

  /* wrap buffer if needed */
  if( CI->writepos >= PKT_BUFFER ){
    CI->writepos = 0;
  }

  /* flag that another packet is ready */
  if ( sem_post(CI->semaphore) != 0 ){
    logmsg(stderr, "sem_post() returned %d: %s\n", errno, strerror(errno));
  }

  return recipient;
}

static int fill_caphead(cap_head* head, struct timeval* tv, size_t bytes, const char* iface, const char* MAMPid){
  head->ts.tv_sec   = tv->tv_sec;   // Store arrival time in seconds
  head->ts.tv_psec  = tv->tv_usec; // Write timestamp in picosec
  head->ts.tv_psec *= 1000000;
  head->len         = bytes;
  strncpy(head->nic, iface, 4);
  strncpy(head->mampid, MAMPid, 8);
  return 0;
}

static void wait_for_auth(){
  while ( terminateThreads == 0 ){
    if ( MAMPid ){
      return;
    }
    sleep(1); /** @todo should use a pthread cond. variable */
  }
}


typedef int (*read_packet_callback)(void* context, unsigned char* dst, struct timeval* timestamp);

struct capture_context {
  read_packet_callback read_packet;
};

static int capture_loop(struct CI* CI, struct capture_context* cap){
  /* wait until the MP is authorized until it starts capture */
  wait_for_auth();

  CI->writepos = 0; /* Reset write-position in memory */
  while(terminateThreads==0){
    /* calculate pointers into writebuffer */
    unsigned char* raw_buffer = datamem[CI->id][CI->writepos];
    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
    unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

    /* read a packet */
    struct timeval timestamp;
    size_t bytes = cap->read_packet(cap, packet_buffer, &timestamp);

    if ( bytes < 0 ){ /* failed to read */
      break;
    } else if ( bytes == 0 ){ /* no data */
      continue;
    }

    /* fill details into capture header */
    fill_caphead(head, &timestamp, bytes, CI->nic, MAMPid);

    /* stats */
    recvPkts++;
    CI->pktCnt++;

    /* return -1 when no filter matches */
    if ( push_packet(CI, whead, head, packet_buffer) == -1 ){
      continue;
    }

    matchPkts++;
  }

  return 0;
}

struct raw_context {
  struct capture_context base;
  int socket;
};

static int read_packet_raw(struct raw_context* ctx, unsigned char* dst, struct timeval* timestamp){
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
      logmsg(stderr, "select() failed with code %d: %s\n", errno, strerror(errno));
      return -1;
    }
  }

  /* read from socket */
  const ssize_t bytes = recvfrom(sd, dst, PKT_CAPSIZE, MSG_TRUNC, NULL, NULL);

  /* check errors */
  if ( bytes == -1 ){
    if ( errno == EAGAIN ){
      return 0;
    }
    int save = errno;
    logmsg(stderr, "recvfrom() failed with code %d: %s\n", save, strerror(save));
    errno = save;
    return -1;
  }

  /* grab timestamp */
  ioctl(sd, SIOCGSTAMP, &timestamp );

  return bytes;
}

/* This is the RAW_SOCKET capturer..   */ 
void* capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct raw_context cap;
  
  /* initialize raw capture */
  logmsg(verbose, "CI[%d] initializing capture on %s using RAW_SOCKET (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);
  cap.socket = CI->sd;

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet_raw;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->nic);

  return NULL;
}

struct pcap_context {
  struct capture_context base;
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];
};

static int read_packet_pcap(struct pcap_context* ctx, unsigned char* dst, struct timeval* timestamp){
  struct pcap_pkthdr pcaphead;	/* pcap.h */
  const u_char* payload = pcap_next(ctx->handle, &pcaphead);
  if(payload==NULL) {
    logmsg(stderr, "CAPTURE_PCAP: Couldnt get payload, %s\n", pcap_geterr(ctx->handle));
    return -1;
  }

  const size_t data_len = MIN(pcaphead.caplen, PKT_CAPSIZE);
  const size_t padding = PKT_CAPSIZE - data_len;

  memcpy(dst, payload, data_len);
  memset(dst + data_len, 0, padding);
  timestamp->tv_sec = pcaphead.ts.tv_sec;
  timestamp->tv_usec = pcaphead.ts.tv_usec;

  return pcaphead.caplen;
}

/* This is the PCAP_SOCKET capturer..   */ 
void* pcap_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct pcap_context cap;

  /* initialize pcap capture */
  logmsg(verbose, "CI[%d] initializing capture on %s using pcap (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);
  cap.handle = pcap_open_live (CI->nic, BUFSIZ, 1, 0, cap.errbuf);   /* open device for reading */
  if ( !cap.handle ) {
    logmsg(stderr, "pcap_open_live(): %s\n", cap.errbuf);
    exit (1);
  }

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet_pcap;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->nic);
  pcap_close(cap.handle);

  return NULL;
}
