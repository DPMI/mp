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

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <pthread.h>

pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

static int push_packet(struct CI* CI, write_head* whead, cap_head* head, const unsigned char* packet_buffer){
  const int recipient = filter(CI->iface, packet_buffer, head);
  if ( recipient == -1 ){ /* no match */
    return -1;
  }
  
  // prevent the reader from operating on the same chunk of memory.
  pthread_mutex_lock( &mutex2 );
  {
    strncpy(head->nic, CI->iface, 4);
    strncpy(head->mampid, MAMPid, 8);
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

int capture_loop(struct CI* CI, struct capture_context* cap){
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
    ssize_t bytes = cap->read_packet(cap, packet_buffer, &timestamp);

    if ( bytes < 0 ){ /* failed to read */
      break;
    } else if ( bytes == 0 ){ /* no data */
      continue;
    }

    /* fill details into capture header */
    fill_caphead(head, &timestamp, bytes, CI->iface, MAMPid);

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
