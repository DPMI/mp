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
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern int counter;
extern char* ebuf;
extern void* dagbuf[];
extern int dagfd[];
extern int skipflag;

pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;

struct sockaddr_ll  from;       //source address


/* This is the RAW_SOCKET capturer..   */ 
/* Lots of problems, use with caution. */
void* capture(void* ptr){
  int sd;                       // the socket
  char nicString[4];            // The CI identifier
  char* nic;                    // name of the network interface
  extern int semaphore;         // semaphore for syncronization
  int id;                       // number of this thread, used for memory access
  capProcess* cProc=0;          // struct with parameters deliverd from main
  cap_head *head;               // pointer cap_head
  write_head *whead;            // pointer write_head
  int fromlen;                  // length of from
  size_t buffsize=PKT_CAPSIZE;  // This is how much we extract from the network.
  int writePos=0;               // Position in memory where to write
  int packet_len=0;             // acctual length of packet
  union semun args;             // argument to semaphore
  struct timeval time;          // arrivaltime
  int consumer;                 // consumer identification.
  int niclen;                   // Lenght of nic string
  cProc=(capProcess*)ptr;
  int myTD=cProc->accuracy;     // Accuracy of this Capture Thread.
  sd=cProc->sd;

  nicString[0]=cProc->nic[0];   // [e]th0\0
  nicString[1]=cProc->nic[3];   // eth[0]\0
  nicString[2]=0;
  nicString[3]=0;
  nic=nicString;

  printf("CAPt: here.\n");
  semaphore=cProc->semaphore;
  id=cProc->id;
  
  niclen=strlen(nic)+1;
  _DEBUG_MSG (fprintf(stderr,"Capture for %s initializing, Memory at %p.\n",nic, &datamem[id]))
  args.val=1;

  struct timeval timeout;
  fd_set fds;
  timeout.tv_sec=5;
  timeout.tv_usec=0;
  FD_ZERO(&fds);
  FD_SET(sd,&fds);
  int selectReturn=0;
  
  while(terminateThreads==0)  {
    _DEBUG_MSG  (fprintf(stderr,"CaptureThread %ld Pkts : %d \n",pthread_self(), recvPkts))
    fromlen = sizeof(from);
    do { // read packet from interface

      while( (selectReturn=select(sd+1,&fds,NULL,NULL, &timeout))<=0 && terminateThreads==0){
	if(terminateThreads!=0){
	  perror("CAPTURE(RAW):Got a break signal.\n");
	  break;
	}
	if(selectReturn==-1){
	  perror("CAPTURE(RAW):Select error:");
	  //EXIT SOMEHOW
	  pthread_exit(NULL);
	} else if(selectReturn==0){
	  FD_SET(sd, &fds);
	  timeout.tv_sec=5;
	  timeout.tv_usec=0;
	}
      }
	  
      packet_len = recvfrom(sd, (&datamem[id][writePos][(sizeof(write_head)+sizeof(cap_head))]),
			    buffsize, MSG_TRUNC,(struct sockaddr *) &from, &fromlen);
    }while (packet_len == -1 && errno == EINTR && terminateThreads==0);
    
    if (packet_len == -1)    {
      if (errno == EAGAIN)
	fprintf(stderr,"CAPTURE_RAW[%s] ERROR Empty\n",nic);
      else
        fprintf(stderr,"CAPTURE_RAW[%s] ERROR %d\n",nic,errno);
    }
    else {
//This could be a problem if a new packet arrivs before timestamp???
      ioctl(sd, SIOCGSTAMP, &time );//get time stamp associated with packet (C/O kernel)
      recvPkts++;
      cProc->pktCnt=cProc->pktCnt+1;

// int filter(void* pkt); 0=> DROP PKT. n, send to recipient n.
      whead=(write_head*)datamem[id][writePos];
      head=(cap_head*)&datamem[id][writePos][sizeof(write_head)];
      consumer=filter(nic,&datamem[id][writePos][(sizeof(write_head)+sizeof(cap_head))],head);
      if(consumer>=0)
      {
	matchPkts++;
//Mutex begin; prevent the reader from operating on the same chunk of memory.
	pthread_mutex_lock( &mutex2 );
	whead=(write_head*)datamem[id][writePos];
	head=(cap_head*)&datamem[id][writePos][sizeof(write_head)];
	head->ts.tv_sec=time.tv_sec;  // Store arrival time in seconds
	head->ts.tv_psec=time.tv_usec;// Write timestamp in picosec
	head->ts.tv_psec*=1000;
	head->ts.tv_psec*=1000;
	head->len=packet_len; // Store packet lenght in header.
                              // head->caplen will set by the filter, when copying data to sender buffer.
	/*head->tsAccuracy=myTD;*/
	strncpy(head->nic,nic,4);
	strncpy(head->mampid,MAMPid,8);
	
	whead->free=whead->free+1; //marks the post that it has been written
	whead->consumer=consumer;  //sets the recipient id.
	
	if(whead->free>1){ //Control buffer overrun
          fprintf(stderr,"OVERWRITING: %ld @ %d for the %d time \n",pthread_self(),writePos,whead->free);
	  fprintf(stderr,"CT: bufferUsage[%d]=%d\n", id,bufferUsage[id]);
	  memDropcount++;
	}
	pthread_mutex_unlock( &mutex2 );
//Mutex end
	packet_len=0;
	if(semctl(semaphore, 0, GETVAL) == 0)  // If already 1, indicating some pkts. Do nothing
	{
          if(semctl(semaphore, 0, SETVAL,args)== -1) // Else set it to ONE!
	    printf("Error setting semaphore.\n");
	  // else Semaphore is set
	}
	writePos++;
	bufferUsage[id]++;
        if(writePos<PKT_BUFFER){
        } else {
	  writePos=0; //when all posts in datamem is written begin from 0 again
        }
      }
      
    }
  }
  // comes here when terminateThreads = 1
  _DEBUG_MSG (fprintf(stderr,"Child %ld My work here is done %s.\n", pthread_self(),nic))
  return(NULL) ;
}



/* This is the PCAP_SOCKET capturer..   */ 
/* Lots of problems, use with caution. */
void* pcap_capture(void* ptr){
  int sd;                       // the socket
//  char nicString[4];            // The CI identifier
  char* nic;                    // name of the network interface
  extern int semaphore;         // semaphore for syncronization
  int id;                       // number of this thread, used for memory access
  capProcess* cProc;            // struct with parameters deliverd from main

  int writePos=0;               // Position in memory where to write
  int packet_len=0;             // acctual length of packet
  union semun args;             // argument to semaphore
//  struct timeval time;          // arrivaltime
  int consumer;                 // consumer identification.
  int niclen;                   // Lenght of nic string
  int myTD;                     // Accuracy of this Capture Thread.;

  cProc=(capProcess*)ptr;
  sd=cProc->sd;
  nic=cProc->nic;
  semaphore=cProc->semaphore;
  id=cProc->id;
  myTD=cProc->accuracy;     
  
  niclen=strlen(nic)+1;
  _DEBUG_MSG (fprintf(stderr,"Capture for %s initializing, Memory at %p.\n",nic, &datamem[id]))
  args.val=1;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr;
  const u_char *payload;
  struct pcap_pkthdr pcaphead;	/* pcap.h */


  _DEBUG_MSG (fprintf(stderr," Open pcap_open_live(%s, %d,1,-1,%p)\n",nic,BUFSIZ,errbuf))
  descr = pcap_open_live (nic, BUFSIZ, 1, 0, errbuf);   /* open device for reading */
  if (NULL == descr)
  {
    printf ("pcap_open_live(): %s\n", errbuf);
    exit (1);
  }

  
  while(terminateThreads==0)  {
    payload = pcap_next(descr, &pcaphead);
    if(payload==NULL) {
      fprintf(stderr, "CAPTURE_PCAP: Couldnt get payload, %s\n", pcap_geterr(descr));
      exit(1);
    }

    const size_t data_len = MIN(pcaphead.caplen, PKT_CAPSIZE);
    const size_t padding = PKT_CAPSIZE - data_len;

    unsigned char* raw_buffer = datamem[id][writePos];

    write_head* whead   = (write_head*)raw_buffer;
    cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
    unsigned char* packet_buffer = raw_buffer + sizeof(write_head) + sizeof(cap_head);

    memcpy(packet_buffer, payload, data_len);
    memset(packet_buffer + data_len, 0, padding);
    
    recvPkts++;
    (cProc->pktCnt)++;

// int filter(void* pkt); 0=> DROP PKT. n, send to recipient n.
    if ( (consumer=filter(nic, packet_buffer, head)) == -1 ){ /* no match */
      continue;
    }

    matchPkts++;
//Mutex begin; prevent the reader from operating on the same chunk of memory.
    pthread_mutex_lock( &mutex2 );
    
    head->ts.tv_sec   = pcaphead.ts.tv_sec;  // Store arrival time in seconds
    head->ts.tv_psec  = pcaphead.ts.tv_usec;// Write timestamp in picosec
    head->ts.tv_psec *= 1000000;
    head->len = pcaphead.len; // Store packet lenght in header.
                              // head->caplen will set by the filter, when copying data to sender buffer.
    /*head->tsAccuracy=myTD; */
    
    strcpy(head->nic, nic);
    strncpy(head->mampid, MAMPid, 8);
    whead->free++; //marks the post that it has been written
    whead->consumer=consumer;  //sets the recipient id.
    
    if(whead->free>1){ //Control buffer overrun
      fprintf(stderr,"OVERWRITING: %ld @ %d for the %d time \n",pthread_self(),writePos,whead->free);
      fprintf(stderr,"CT: bufferUsage[%d]=%d\n", id,bufferUsage[id]);
    }
    
    pthread_mutex_unlock( &mutex2 );
    //Mutex end
    packet_len=0;
    if(semctl(semaphore, 0, GETVAL) == 0)  // If already 1, indicating some pkts. Do nothing
      {
	if(semctl(semaphore, 0, SETVAL,args)== -1) // Else set it to ONE!
	  printf("Error setting semaphore.\n");
	// else Semaphore is set
      }
    writePos++;
    bufferUsage[id]++;
    if(writePos<PKT_BUFFER){
    } else {
      writePos=0; //when all posts in datamem is written begin from 0 again
    }
  }

  // comes here when terminateThreads = 1
  if(semctl(semaphore, 0, SETVAL,args)== -1) // Else set it to ZERO!
    fprintf(stderr,"capture: Error setting semaphore.\n");

  _DEBUG_MSG (fprintf(stderr,"Child %ld My work here is done %s.\n", pthread_self(),nic))
    return(NULL) ;
}




