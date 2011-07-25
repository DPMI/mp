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
    mampid_set(head->mampid, MPinfo->id);
    whead->free++; //marks the post that it has been written
    whead->consumer = recipient;
    CI->buffer_usage++;
  
    if ( whead->free>1 ){ //Control buffer overrun
      logmsg(stderr, "CI[%d] OVERWRITING: %ld @ %d for the %d time \n", CI->id, pthread_self(), CI->writepos, whead->free);
      logmsg(stderr, "CI[%d] bufferUsage=%d\n", CI->id, CI->buffer_usage);
    }
  }
  pthread_mutex_unlock( &mutex2 );

  /* increment write position */
  CI->writepos = (CI->writepos+1) % PKT_BUFFER;
      
  /* flag that another packet is ready */
  if ( sem_post(CI->semaphore) != 0 ){
    logmsg(stderr, "sem_post() returned %d: %s\n", errno, strerror(errno));
  }

  return recipient;
}

static int fill_caphead(cap_head* head, const char* iface, const char* MAMPid){
  /* reset caphead to it won't contain any garbage */
  memset(head, 0, sizeof(cap_head));

  strncpy(head->nic, iface, 4);
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
  /* flag that thread is ready for capture */
  sem_post(CI->flag);

  /* wait until the MP is authorized until it starts capture */
  wait_for_auth();

  CI->writepos = 0; /* Reset write-position in memory */
  while(terminateThreads==0){
    /* calculate pointers into writebuffer */
    unsigned char* raw_buffer = datamem[CI->id][CI->writepos];
    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
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
    MPstats->packet_count++;
    CI->packet_count++;

    /* return -1 when no filter matches */
    if ( push_packet(CI, whead, head, packet_buffer) == -1 ){
      continue;
    }

    /* stats */
    MPstats->matched_count++;
    CI->matched_count++;
  }

  return 0;
}

void consumer_init(struct consumer* con, int index, unsigned char* buffer){
  con->stream = NULL;
  con->index = index;
  con->status = 0;
  
  con->dropCount=0;

  con->ethhead=(struct ethhdr*)buffer; // pointer to ethernet header.
  con->ethhead->h_proto=htons(MYPROTO);    // Set the protocol field of the ethernet header.
  
  //memcpy(con->ethhead->h_dest, dest_mac, ETH_ALEN);
  //memcpy(con->ethhead->h_source, my_mac, ETH_ALEN);
  
  con->shead=(struct sendhead*)(buffer+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
  con->shead->sequencenr=htons(0x0000);    // Initialize the sequencenr to zero.
  con->shead->nopkts=htons(0);                    // Initialize the number of packet to zero
  con->shead->flush=htons(0);                     // Initialize the flush indicator.
  con->shead->version.major=htons(CAPUTILS_VERSION_MAJOR); // Specify the file format used, major number
  con->shead->version.minor=htons(CAPUTILS_VERSION_MINOR); // Specify the file format used, minor number
  /*shead[i]->losscounter=htons(0); */

  con->sendpointer=buffer+sizeof(struct ethhdr)+sizeof(struct sendhead);            // Set sendpointer to first place in sendmem where the packets will be stored.
  con->sendptrref=con->sendpointer;          // Grab a copy of the pointer, simplifies treatment when we sent the packets.
  con->sendcount=0;                        // Initialize the number of pkt stored in the packet, used to determine when to send the packet.
}

void consumer_init_all(){
  for( int i=0; i<CONSUMERS; i++) {
    consumer_init(&MAsd[i], i, sendmem[i]);
  }
}
