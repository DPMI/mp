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
#include "capture.h"
#include "sender.h"
#include <errno.h>
#include <string.h>

#define SEMAPHORE_TIMEOUT_SEC 1

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

int wait_for_capture(sem_t* sem){
  struct timespec ts;

  if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
    int saved = errno;
    fprintf(stderr, "clock_gettime() returned %d: %s\n", saved, strerror(saved));
    return errno;
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

  con->shead->nopkts = htons(con->sendcount); //maSendsize;
  /*con->shead->losscounter=htons((globalDropcount+memDropcount)-dropCount[whead->consumer]); */
  con->dropCount = globalDropcount+memDropcount;

  {
    const u_char* data = con->sendptrref;
    size_t data_size = payload_size;
    
    if ( con->want_sendhead ){
      data -= header_size;
      data_size += header_size;
    }
    
    con->stream->write(con->stream, data, data_size);
  }

  uint32_t seqnr = ntohl(con->shead->sequencenr);

  printf("SendThread %d sending: size: %zd\n", (int)pthread_self(), payload_size);
  printf("\tcaputils-%d.%d\n", ntohs(con->shead->version.major), ntohs(con->shead->version.minor));
  printf("\tdropCount[] = %d (g%d/m%d)\n", con->dropCount, globalDropcount, memDropcount);
  printf("\tPacket length = %ld bytes, Eth %ld, Send %ld, Cap %ld bytes\n", packet_full_size, sizeof(struct ethhdr), sizeof(struct sendhead), sizeof(struct cap_header));
  printf("\tSeqnr  = %04lx \t nopkts = %04x \t Losscount = %d\n", (unsigned long int)seqnr, ntohs(con->shead->nopkts), -1);
  
  //Update the sequence number.
  con->shead->sequencenr = htonl(ntohl(con->shead->sequencenr)+1);
  if ( ntohl(con->shead->sequencenr) > 0xFFFF ){
    con->shead->sequencenr = htonl(0);
  }
  
  writtenPkts += con->sendcount;// Update the total number of sent pkts. 
  con->sendcount = 0;// Clear the number of packets in this sendbuffer
  bzero(con->sendptrref,(maSendsize*(sizeof(cap_head)+PKT_CAPSIZE))); //Clear the memory location, for the packet data. 
  con->sendpointer=con->sendptrref; // Restore the pointer to the first spot where the next packet will be placed.
}

void* sender(void *ptr){
    send_proc_t* proc = (send_proc_t*)ptr;      // Extract the parameters that we got from our master, i.e. parent process..
    const int nics = proc->nics;             // The number of CIs I need to handle. 
    sem_t* semaphore = proc->semaphore;   // Semaphore stuff.

    int readPos[CI_NIC];               // array of memory positions
    int i;                           // index to active memory area

    int exitnr=0;                      // flag for exit
    int nextPDUlen=0;                  // The length of PDUs stored in the selected consumer.

    sentPkts = 0;                    // Total number of mp_packets that I've passed into a sendbuffer. 
    writtenPkts = 0;                 // Total number of mp_packets that I've acctually sent to the network. Ie. sentPkts-writtenPkts => number of packets present in the send buffers. 
    printf("Sender Initializing. There are %d captures.\n", nics);
    for(i=0;i<nics;i++){
      readPos[i] = 0;  // start all reading att position 0
    }

//this turns to 1 when terminateThreads=1 and there are no more packets to send
    while( exitnr==0 ){
      //Find who's next.
      int oldest=-1;
      //      printf("ST: Search.\n");
      while( oldest == -1 && exitnr==0 ){       // Loop while we havent gotten any pkts.
	struct picotime timeOldest;        // timestamp of oldest packet
	timeOldest.tv_sec = UINT32_MAX;
	timeOldest.tv_psec = UINT64_MAX;

	for( i=0; i < nics; i++){                //check all the nics and look for new packet
	  unsigned char* raw_buffer = datamem[i][readPos[i]];
	  write_head* whead   = (write_head*)raw_buffer;
	  cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));

	  /* no packages yet */
	  if( whead->free == 0 ) {
	    continue;
	  }

	  if( timecmp(&head->ts, &timeOldest) < 0 ){
	    timeOldest.tv_sec  = head->ts.tv_sec;
	    timeOldest.tv_psec = head->ts.tv_psec;
	    oldest = i;
	  }
	} //end for loop

	if(terminateThreads>0) {
	  //Problems, We have tried to kill it multiple times..  
	  // DIE DIE you evil thread!
	  exitnr=1;
	  break;
	}

	//No new pkts have arrived. Wait for a signal from one of the capture threads.
	if ( oldest==-1 ){ 
	  wait_for_capture(semaphore);
	}
      } // End while loop. Oldest now contains an index to the oldest packet
      
      /* couldn't find a packet, gave up waiting. we are probably terminating. */
      if ( oldest == -1 ){
	continue;
      }

      unsigned char* raw_buffer = datamem[oldest][readPos[oldest]];
      write_head* whead   = (write_head*)raw_buffer;
      cap_head* head      = (cap_head*)(raw_buffer + sizeof(write_head));
      struct consumer* con = &MAsd[whead->consumer];

      const size_t packet_size = sizeof(cap_head)+head->caplen;

      //	printf("readPos[oldest] = %d \n", readPos[oldest]);
      //  pthread_mutex_lock( &mutex1 );
      whead->free=0; // Let the capture_nicX now that we have read it.
      //  pthread_mutex_unlock( &mutex1 );
      readPos[oldest]++; // update the read position.
      if(readPos[oldest]>=PKT_BUFFER){
	readPos[oldest]=0;//when all posts in datamem is read begin from 0 again
      }
      bufferUsage[oldest]--;
      //	printf("ST: bufferUsage[%d]=%d\n", oldest,bufferUsage[oldest]);
      if(bufferUsage[oldest]<0){
	bufferUsage[oldest]=0;
      }
      //      These two rows were used when we used FIXED payload lenghts, PKT_CAPSIZE. 
      //	memcpy(sendpointer[whead->consumer],head,(sizeof(cap_head)+PKT_CAPSIZE)); //copy the packet to the sendbuffer
      //	sendpointer[whead->consumer]+=(sizeof(cap_head)+PKT_CAPSIZE);// Update the send pointer.

      //      These two rows use variable capture lengths. 

      memcpy(con->sendpointer, head, packet_size);// copy the packet to the sendbuffer
      memset(head, 0, sizeof(cap_head) + PKT_CAPSIZE);// Clear the memory where we read the packet. ALWAYS clear the full caplen.

      con->sendpointer += packet_size; // Update the send pointer.
      con->sendcount += 1;

      nextPDUlen = head->caplen;
      sentPkts++;

      const size_t payload_size = con->sendpointer - con->sendptrref;
      const size_t mtu_size = MAmtu-2*(sizeof(cap_head)+nextPDUlen); // This row accounts for the fact that the consumer buffers only need extra space for one PDU of of the capture size for that particular filter. 

      /* still not enough payload, wait for more */
      if( payload_size < mtu_size ){
	continue;
      }

      send_packet(con);

      if( terminateThreads > 0 ){ // program is ending and all packets are sent
	exitnr=1;
      }
    }// End of while(exitnr==0) 

    // Flush all buffers..
    printf("Flushing sendbuffers.\n");
    for(i=0;i<CONSUMERS;i++){
      flushBuffer(i);
    }

    //comes here when exitnr =1    
    printf("Sender Child %ld My work here is done .\n", pthread_self());
    return(NULL) ;
}
