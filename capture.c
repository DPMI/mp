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

struct sockaddr_ll  from;       //source address


/* This is the RAW_SOCKET capturer..   */ 
/* Lots of problems, use with caution. */
void* capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;

  //int sd;                       // the socket
  //  char nicString[4];            // The CI identifier
  //char* nic;                    // name of the network interface
  //int id;                       // number of this thread, used for memory access
  cap_head *head;               // pointer cap_head
  write_head *whead;            // pointer write_head
  socklen_t fromlen;                  // length of from
  size_t buffsize=PKT_CAPSIZE;  // This is how much we extract from the network.
  int writePos=0;               // Position in memory where to write
  int packet_len=0;             // acctual length of packet
  struct timeval time;          // arrivaltime
  int consumer;                 // consumer identification.

  //nicString[0]=cProc->nic[0];   // [e]th0\0
  //nicString[1]=cProc->nic[3];   // eth[0]\0
  //nicString[2]=0;
  //nicString[3]=0;
  //nic=nicString;

  printf("CAPt: here.\n");
  //sem_t* semaphore=cProc->semaphore;
  //id=cProc->id;
  
  logmsg(verbose, "Capture for %s initializing, Memory at %p.\n", CI->nic, &datamem[CI->id]);

  struct timeval timeout;
  fd_set fds;
  timeout.tv_sec=5;
  timeout.tv_usec=0;
  FD_ZERO(&fds);
  FD_SET(CI->sd, &fds);
  int selectReturn=0;
  
  while(terminateThreads==0)  {
    fprintf(verbose, "CaptureThread %ld Pkts : %d \n",pthread_self(), recvPkts);
    fromlen = sizeof(from);
    do { // read packet from interface

      while( (selectReturn=select(CI->sd+1,&fds,NULL,NULL, &timeout))<=0 && terminateThreads==0){
	if(terminateThreads!=0){
	  perror("CAPTURE(RAW):Got a break signal.\n");
	  break;
	}
	if(selectReturn==-1){
	  perror("CAPTURE(RAW):Select error:");
	  //EXIT SOMEHOW
	  pthread_exit(NULL);
	} else if(selectReturn==0){
	  FD_SET(CI->sd, &fds);
	  timeout.tv_sec=5;
	  timeout.tv_usec=0;
	}
      }
	  
      packet_len = recvfrom(CI->sd, (&datamem[CI->id][writePos][(sizeof(write_head)+sizeof(cap_head))]),
			    buffsize, MSG_TRUNC,(struct sockaddr *) &from, &fromlen);
    }while (packet_len == -1 && errno == EINTR && terminateThreads==0);
    
    if (packet_len == -1)    {
      if (errno == EAGAIN)
	fprintf(stderr,"CAPTURE_RAW[%s] ERROR Empty\n", CI->nic);
      else
        fprintf(stderr,"CAPTURE_RAW[%s] ERROR %d: %s\n", CI->nic, errno, strerror(errno));
    }
    else {
//This could be a problem if a new packet arrivs before timestamp???
      ioctl(CI->sd, SIOCGSTAMP, &time );//get time stamp associated with packet (C/O kernel)
      recvPkts++;
      CI->pktCnt++;

// int filter(void* pkt); 0=> DROP PKT. n, send to recipient n.
      whead=(write_head*)datamem[CI->id][writePos];
      head=(cap_head*)&datamem[CI->id][writePos][sizeof(write_head)];
      consumer=filter(CI->nic, &datamem[CI->id][writePos][(sizeof(write_head)+sizeof(cap_head))], head);
      if(consumer>=0)
      {
	matchPkts++;
//Mutex begin; prevent the reader from operating on the same chunk of memory.
	pthread_mutex_lock( &mutex2 );
	whead=(write_head*)datamem[CI->id][writePos];
	head=(cap_head*)&datamem[CI->id][writePos][sizeof(write_head)];
	head->ts.tv_sec=time.tv_sec;  // Store arrival time in seconds
	head->ts.tv_psec=time.tv_usec;// Write timestamp in picosec
	head->ts.tv_psec*=1000;
	head->ts.tv_psec*=1000;
	head->len=packet_len; // Store packet lenght in header.
                              // head->caplen will set by the filter, when copying data to sender buffer.
	/*head->tsAccuracy=myTD;*/
	strncpy(head->nic, CI->nic,4);
	strncpy(head->mampid, MAMPid,8);
	
	whead->free=whead->free+1; //marks the post that it has been written
	whead->consumer=consumer;  //sets the recipient id.
	
	if(whead->free>1){ //Control buffer overrun
          fprintf(stderr,"OVERWRITING: %ld @ %d for the %d time \n",pthread_self(),writePos,whead->free);
	  fprintf(stderr,"CT: bufferUsage[%d]=%d\n", CI->id, CI->bufferUsage);
	  memDropcount++;
	}
	pthread_mutex_unlock( &mutex2 );
//Mutex end
	packet_len=0;

	if ( sem_post(CI->semaphore) != 0 ){
	  fprintf(stderr, "sem_post() returned %d: %s\n", errno, strerror(errno));
	}

	writePos++;
	CI->bufferUsage++;
        if(writePos<PKT_BUFFER){
        } else {
	  writePos=0; //when all posts in datamem is written begin from 0 again
        }
      }
      
    }
  }
  // comes here when terminateThreads = 1
  fprintf(verbose, "Child %ld My work here is done %s.\n", pthread_self(), CI->nic);
  return(NULL) ;
}

/* This is the PCAP_SOCKET capturer..   */ 
/* Lots of problems, use with caution. */
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

  while(terminateThreads==0)  {
    const u_char* payload = pcap_next(descr, &pcaphead);
    if(payload==NULL) {
      logmsg(stderr, "CAPTURE_PCAP: Couldnt get payload, %s\n", pcap_geterr(descr));
      exit(1);
    }

    const size_t data_len = MIN(pcaphead.caplen, PKT_CAPSIZE);
    const size_t padding = PKT_CAPSIZE - data_len;

    unsigned char* raw_buffer = datamem[CI->id][CI->writepos];

    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
    unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

    head->ts.tv_sec   = pcaphead.ts.tv_sec;  // Store arrival time in seconds
    head->ts.tv_psec  = pcaphead.ts.tv_usec;// Write timestamp in picosec
    head->ts.tv_psec *= 1000000;
    head->len = pcaphead.len; // Store packet lenght in header.
                              // head->caplen will set by the filter, when copying data to sender buffer.
    /*head->tsAccuracy=myTD; */

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
