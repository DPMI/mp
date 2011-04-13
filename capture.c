/***************************************************************************
                          capture.c  -  description
                             -------------------
    begin                : Tue Nov 26 2002
    copyright            : (C) 2002 by Anders Ekberg
                           (C) 2002-2005 by Patrik Arlos (PAL)
    email                : anders.ekberg@bth.se
                           patrik.arlos@bth.se
                           rasmus.melgaard@bth.se

    changelog
    2005-03-05           Merged in pcap version(RMA) of capture. (PAL)
    2008-04-02           Misc. changes, moving up to version 0.6
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

/* This is the RAW_SOCKET capturer..   */ 
/* Lots of problems, use with caution. */
void* capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  CI->writepos = 0; /* Reset write-position in memory */
  //  myTD=cProc->accuracy;
  
  logmsg(verbose, "CI[%d] initializing capture on %s using RAW_SOCKET (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);

  wait_for_auth();
  while( terminateThreads==0 )  {
   
    /* wait until data is available on socket */
    {
      struct timeval timeout = {1, 0};
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(CI->sd, &fds);
      
      if ( select(CI->sd+1,&fds,NULL,NULL, &timeout) == -1 ){
	switch ( errno ){
	case EAGAIN:
	case EINTR:
	  continue;
	  
	default:
	  logmsg(stderr, "select() failed with code %d: %s\n", errno, strerror(errno));
	  abort();
	}
      }
    }

    unsigned char* raw_buffer = datamem[CI->id][CI->writepos];
    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
    unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

    const ssize_t bytes = recvfrom(CI->sd, packet_buffer, PKT_CAPSIZE, MSG_TRUNC, NULL, NULL);

    if ( bytes == -1 ){
      if ( errno == EAGAIN ){
	continue;
      }
      logmsg(stderr, "recvfrom() failed with code %d: %s\n", errno, strerror(errno));
      abort();
    }

    //This could be a problem if a new packet arrivs before timestamp???
    struct timeval time;
    ioctl(CI->sd, SIOCGSTAMP, &time );//get time stamp associated with packet (C/O kernel)

    fill_caphead(head, &time, bytes, CI->nic, MAMPid);

    recvPkts++;
    CI->pktCnt++;

    /* return -1 when no filter matches */
    if ( push_packet(CI, whead, head, packet_buffer) == -1 ){
      continue;
    }

    matchPkts++;
  }

  // comes here when terminateThreads = 1
  fprintf(verbose, "Child %ld My work here is done %s.\n", pthread_self(), CI->nic);
  return(NULL) ;
}

/* This is the PCAP_SOCKET capturer..   */ 
void* pcap_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  CI->writepos = 0; /* Reset write-position in memory */
  //  myTD=cProc->accuracy;     
  
  logmsg(verbose, "CI[%d] initializing capture on %s using pcap (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);

  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr pcaphead;	/* pcap.h */

  pcap_t* descr = pcap_open_live (CI->nic, BUFSIZ, 1, 0, errbuf);   /* open device for reading */
  if (NULL == descr) {
    logmsg(stderr, "pcap_open_live(): %s\n", errbuf);
    exit (1);
  }

  wait_for_auth();
  while(terminateThreads==0)  {
    const u_char* payload = pcap_next(descr, &pcaphead);
    if(payload==NULL) {
      logmsg(stderr, "CAPTURE_PCAP: Couldnt get payload, %s\n", pcap_geterr(descr));
      exit(1);
    }

    unsigned char* raw_buffer = datamem[CI->id][CI->writepos];
    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
    unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

    const size_t data_len = MIN(pcaphead.caplen, PKT_CAPSIZE);
    const size_t padding = PKT_CAPSIZE - data_len;

    fill_caphead(head, &pcaphead.ts, pcaphead.len, CI->nic, MAMPid);

    memcpy(packet_buffer, payload, data_len);
    memset(packet_buffer + data_len, 0, padding);
    
    recvPkts++;
    CI->pktCnt++;

    /* return -1 when no filter matches */
    if ( push_packet(CI, whead, head, packet_buffer) == -1 ){
      continue;
    }

    matchPkts++;
  }

  logmsg(verbose, "Child %ld My work here is done %s.\n", pthread_self(), CI->nic);
  return(NULL) ;
}
