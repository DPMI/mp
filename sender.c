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

void* sender(void *ptr){
    sendProcess* mySend;
    int nics;                          //number of capture nics
    //    cap_head *head;                    // pointer cap_head
    //    write_head *whead;                 // pointer write_head
    //void *outbuffer;                   // pointer to packet to send
    int readPos[CI_NIC];               // array of memory positions
    int i;                           // index to active memory area
    unsigned char dest_mac[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    int exitnr=0;                      // flag for exit
    int nextPDUlen=0;                  // The length of PDUs stored in the selected consumer.

    printf("ST: Initializing sendpointers. \n");
    printf("Version : %s .\n", CAPUTILS_VERSION);
    for(i=0;i<CONSUMERS;i++){
      MAsd[i].status=0;
      MAsd[i].dropCount=0;
      MAsd[i].ethhead=(struct ethhdr*)sendmem[i]; // pointer to ethernet header.

      memcpy(MAsd[i].ethhead->h_dest, dest_mac, ETH_ALEN);
      memcpy(MAsd[i].ethhead->h_source, my_mac, ETH_ALEN);

      MAsd[i].ethhead->h_proto=htons(MYPROTO);    // Set the protocol field of the ethernet header.
      MAsd[i].ethhead->h_dest[5]=i;               // Adjust the mutlicast address last byte to become [i].. Dirty but works... 
      MAsd[i].shead=(struct sendhead*)(sendmem[i]+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
      MAsd[i].shead->sequencenr=htons(0x0000);    // Initialize the sequencenr to zero.
      MAsd[i].shead->nopkts=htons(0);                    // Initialize the number of packet to zero
      MAsd[i].shead->flush=htons(0);                     // Initialize the flush indicator.
      MAsd[i].shead->version.major=CAPUTILS_VERSION_MAJOR; // Specify the file format used, major number
      MAsd[i].shead->version.minor=CAPUTILS_VERSION_MINOR; // Specify the file format used, minor number
      /*shead[i]->losscounter=htons(0); */
      MAsd[i].sendpointer=sendmem[i]+sizeof(struct ethhdr)+sizeof(struct sendhead);            // Set sendpointer to first place in sendmem where the packets will be stored.
      MAsd[i].sendptrref=MAsd[i].sendpointer;          // Grab a copy of the pointer, simplifies treatment when we sent the packets.
      MAsd[i].sendcount=0;                        // Initialize the number of pkt stored in the packet, used to determine when to send the packet.
    }
    printf("ST: eof dirty works.\n");
    mySend = (sendProcess*)ptr;      // Extract the parameters that we got from our master, i.e. parent process..
    nics = mySend->nics;             // The number of CIs I need to handle. 
    sem_t* semaphore = mySend->semaphore;   // Semaphore stuff.
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
      const size_t packet_full_size = sizeof(struct ethhdr)+sizeof(struct sendhead)+payload_size; /* includes ethernet, sendheader and payload */
      const size_t mtu_size = MAmtu-2*(sizeof(cap_head)+nextPDUlen); // This row accounts for the fact that the consumer buffers only need extra space for one PDU of of the capture size for that particular filter. 

      /* still not enough payload, wait for more */
      if( payload_size < mtu_size ){
	continue;
      }
      
      memcpy(socket_address.sll_addr, con->ethhead->h_dest, ETH_ALEN);
	  
      con->shead->nopkts = htons(con->sendcount); //maSendsize;
      /*con->shead->losscounter=htons((globalDropcount+memDropcount)-dropCount[whead->consumer]); */
      con->dropCount = globalDropcount+memDropcount;

      {
	const u_char* data = con->sendptrref;
	size_t data_size = payload_size;

	if ( con->want_sendhead ){
	  size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
	  data -= header_size;
	  data_size += header_size;
	}

	con->stream->write(con->stream, data, data_size);
      }

      /* 	  switch(consumerType[whead->consumer]){ */
      /* 	    case 3: */
      /* 	      printf("Sending TCP.\t"); */
      /* 	      written = write(MAsd[whead->consumer], */
      /* 			      sendmem[whead->consumer]+sizeof(struct ethhdr)+sizeof(struct sendhead), */
      /* 			      (sendpointer[whead->consumer]-sendptrref[whead->consumer])); */
      /* 	      printf("Sent %d bytes.\n",written); */
      /* 	      break; */
      /* 	    case 2: */
      /* 	      printf("Sending UDP .\t"); */
      /* 	      written = write(MAsd[whead->consumer], */
      /* 			     sendmem[whead->consumer]+sizeof(struct ethhdr), */
      /* 			      sizeof(struct sendhead)+(sendpointer[whead->consumer]-sendptrref[whead->consumer])); */
      /* 	      printf("Sent %d bytes.\n",written); */
      /* 	      break; */
      /* 	    case 1: */
      /* 	      if(ntohl((shead[whead->consumer]->sequencenr))%1==0){ */
      /* 		printf("Sending Ethernet.\t"); */
      /* 		printf("%02X:%02X:%02X:%02X:%02X:%02X-->%02X:%02X:%02X:%02X:%02X:%02X \t",ethhead[whead->consumer]->h_source[0],ethhead[whead->consumer]->h_source[1],ethhead[whead->consumer]->h_source[2],ethhead[whead->consumer]->h_source[3],ethhead[whead->consumer]->h_source[4],ethhead[whead->consumer]->h_source[5],ethhead[whead->consumer]->h_dest[0],ethhead[whead->consumer]->h_dest[1],ethhead[whead->consumer]->h_dest[2],ethhead[whead->consumer]->h_dest[3],ethhead[whead->consumer]->h_dest[4],ethhead[whead->consumer]->h_dest[5]); */
      /* 		printf("seqnr = %04x \n", ntohl(shead[whead->consumer]->sequencenr)); */
      /* 	      } */
      /* 	      written = sendto(MAsd[whead->consumer],  */
      /* 			   sendmem[whead->consumer],  */
      /* 			   sizeof(struct ethhdr)+sizeof(struct sendhead)+(sendpointer[whead->consumer]-sendptrref[whead->consumer]),//sizeof(struct sendhead)+sendcount[whead->consumer]*(sizeof(cap_head)+PKT_CAPSIZE)), */
      /* 			   0,(struct sockaddr*)&socket_address, sizeof(socket_address)); */
      /* //	      if(ntohl((shead[whead->consumer]->sequencenr))%1000==0){ */
      /* //		printf("Sent %d bytes.\n",written); */
      /* //	      } */
      /* 	      break; */
      /* 	    case 0: */
	      
      /* 	      if(ntohl((shead[whead->consumer]->sequencenr))%1==0){ */
      /* 		printf("Saving to file. (fd=%d)\n",MAsd[whead->consumer]); */
      /* 	      } */
      /* 	      written = write(MAsd[whead->consumer],sendmem[whead->consumer]+sizeof(struct ethhdr)+sizeof(struct sendhead),(sendpointer[whead->consumer]-sendptrref[whead->consumer])); */
      /* 	      break; */
      /* 	  } */

      uint32_t seqnr = ntohl(con->shead->sequencenr);

      printf("SendThread %d sending: size: %zd > mtu-pdu: %ld\n", (int)pthread_self(), payload_size, mtu_size);
      printf("\tcaputils-%d.%d\n", con->shead->version.major, con->shead->version.minor);
      printf("\tdropCount[] = %d (g%d/m%d)\n", con->dropCount, globalDropcount, memDropcount);
      printf("\tPacket length = %ld bytes, Eth %ld, Send %ld, Cap %ld bytes\n", packet_full_size, sizeof(struct ethhdr), sizeof(struct sendhead), sizeof(struct cap_header));
      printf("\tSeqnr  = %04lx \t nopkts = %04x \t Losscount = %d\n", (unsigned long int)seqnr, ntohs(con->shead->nopkts), -1);

      //Update the sequence number.
      con->shead->sequencenr=htonl(ntohl(con->shead->sequencenr)+1);
      if ( ntohl(con->shead->sequencenr)>0xFFFF ){
	con->shead->sequencenr=htonl(0);
      }

      writtenPkts += con->sendcount;// Update the total number of sent pkts. 
      con->sendcount=0;// Clear the number of packets in this sendbuffer
      bzero(con->sendptrref,(maSendsize*(sizeof(cap_head)+PKT_CAPSIZE))); //Clear the memory location, for the packet data. 
      con->sendpointer=con->sendptrref; // Restore the pointer to the first spot where the next packet will be placed.

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
