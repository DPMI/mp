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


pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

void* sender(void *ptr){
    sendProcess* mySend;
    int nics;                          //number of capture nics
    extern int semaphore;              // semaphore for syncronization
    cap_head *head;                    // pointer cap_head
    write_head *whead;                 // pointer write_head
    void *outbuffer;                   // pointer to packet to send
    int readPos[CI_NIC];               // array of memory positions
    int written=0;                       // bytes sent
    int i,k;                           // index to active memory area
    int first,oldest;                  // flags
    struct picotime timeOldest;        // timestamp of oldest packet
    struct sembuf sWait = {0, -1, 0};  // set to wait until semaphore == 0 
    union semun sSet;                  // set semaphore == 1 
    unsigned char dest_mac[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    int exitnr=0;                      // flag for exit
    whead=0;
    int nextPDUlen=0;                  // The length of PDUs stored in the selected consumer.

    printf("ST: Initializing sendpointers. \n");
    printf("Version : %s .\n", CAPUTILS_VERSION);
    for(i=0;i<CONSUMERS;i++){
      consumerStatus[i]=0;
      consumerType[i]=-1;
      dropCount[i]=0;
      ethhead[i]=(struct ethhdr*)sendmem[i]; // pointer to ethernet header.
      for(k=0;k<ETH_ALEN;k++){
	ethhead[i]->h_dest[k]=dest_mac[k];   // Set the destination address, defaults to 0x01:00:00:00:[i]
	ethhead[i]->h_source[k]=my_mac[k];   // Set the source address, i.e. the MA nics hwaddress.
      }
      ethhead[i]->h_proto=htons(MYPROTO);    // Set the protocol field of the ethernet header.
      ethhead[i]->h_dest[5]=i;               // Adjust the mutlicast address last byte to become [i].. Dirty but works... 
      shead[i]=(struct sendhead*)(sendmem[i]+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
      shead[i]->sequencenr=htons(0x0000);    // Initialize the sequencenr to zero.
      shead[i]->nopkts=htons(0);                    // Initialize the number of packet to zero
      shead[i]->flush=htons(0);                     // Initialize the flush indicator.
      shead[i]->version.major=CAPUTILS_VERSION_MAJOR; // Specify the file format used, major number
      shead[i]->version.minor=CAPUTILS_VERSION_MINOR; // Specify the file format used, minor number
      /*shead[i]->losscounter=htons(0); */
      sendpointer[i]=sendmem[i]+sizeof(struct ethhdr)+sizeof(struct sendhead);            // Set sendpointer to first place in sendmem where the packets will be stored.
      sendptrref[i]=sendpointer[i];          // Grab a copy of the pointer, simplifies treatment when we sent the packets.
      sendcount[i]=0;                        // Initialize the number of pkt stored in the packet, used to determine when to send the packet.
    }
    printf("ST: eof dirty works.\n");
    sSet.val = 1;
    mySend = (sendProcess*)ptr;      // Extract the parameters that we got from our master, i.e. parent process..
    nics = mySend->nics;             // The number of CIs I need to handle. 
    semaphore = mySend->semaphore;   // Semaphore stuff.
    sentPkts = 0;                    // Total number of mp_packets that I've passed into a sendbuffer. 
    writtenPkts = 0;                 // Total number of mp_packets that I've acctually sent to the network. Ie. sentPkts-writtenPkts => number of packets present in the send buffers. 
    printf("Sender Initializing. There are %d captures.\n", nics);
    first=0;
    for(i=0;i<nics;i++){
      readPos[i] = 0;  // start all reading att position 0
    }

//this turns to 1 when terminateThreads=1 and there are no more packets to send
    while(exitnr==0){
      //Find who's next.
      oldest=-1;
      //      printf("ST: Search.\n");
      while(oldest==-1 && exitnr==0){       // Loop while we havent gotten any pkts.
	for(i=0;i<nics;i++){                //check all the nics and look for new packet
	  //printf("Checking nic %d\n",i);
	  whead=(write_head*)datamem[i][readPos[i]];
	  head=(cap_head*)&datamem[i][readPos[i]][sizeof(write_head)];
	  if(whead->free==1) {
	    if(oldest==-1){                 // first new packet detected
	      // No one has been checked prior to this.
	      timeOldest.tv_sec=head->ts.tv_sec;
	      timeOldest.tv_psec=head->ts.tv_psec;
	      oldest=i;
	    } else { // multiple packet have arrived must see who is first
	      if(head->ts.tv_sec <= timeOldest.tv_sec && head->ts.tv_psec < timeOldest.tv_psec){
		timeOldest.tv_sec=head->ts.tv_sec;
		timeOldest.tv_psec=head->ts.tv_psec;
		oldest=i;
	      }
	    }
	  } else{  //No packets found
	    // wait for semaphore.
	  }
	} //end for loop
	//	printf("Nic %d contains the oldest frame.\n",oldest);

	if(terminateThreads>0) {
	  //Problems, We have tried to kill it multiple times..  
	  // DIE DIE you evil thread!
	  exitnr=1;
	}

	if(oldest==-1){//No new pkts have arrived. Wait for a signal from one of the capture threads.
	  i=0;
	  //	  printf("SENDER: Waiting for semaphore.\n");fflush(stdout);
	  if (semop(semaphore, &sWait, 1) == -1){  // Wait for the semaphore to be ZERO.
	    printf("ST: Semaphore problem, did I wait or not? terminateThread = %d \n",terminateThreads);
	    i=errno;
	    if(i==E2BIG)printf("The argument nsops is greater than SEMOPM, the maximum number of operations allowed per system call.\n");
	    if(i==EACCES)printf("The calling process has no access permissions on the semaphore set as required by one of the specified operations.\n");
	    if(i==EAGAIN)printf("An operation could not go through and IPC_NOWAIT was asserted in its sem_flg.\n");
	    if(i==EFAULT)printf("The address pointed to by sops isn't accessible.\n");
	    if(i==EFBIG)printf("For some operation the value of sem_num is less than 0 or greater than or equal to the number of semaphores in the set.\n");
	    if(i==EIDRM)printf("The semaphore set was removed.\n");
	    if(i==EINTR)printf("Sleeping on a wait queue, the process received a signal that had to be caught.\n");
	    if(i==EINVAL)printf("The semaphore set doesn't exist, or semid is less than zero, or nsops has anon-positive value.\n");
	    if(i==ENOMEM)printf("The sem_flg of some operation asserted SEM_UNDO and the system has not enough memory to allocate the undo structure.\n");
	    if(i==ERANGE)printf("For some operation semop+semval is greater than SEMVMX, the implementation dependent maximum value for semval.\n");
	  }
	  //	  printf("SENDER: SEMAPHORE wait is now done, left without failiure?\n");fflush(stdout);
	}//end semaphores and go back to travers the memory
      } // End while loop. Oldest now contains an index to the oldest packet
      if(exitnr==0){
	outbuffer=&datamem[oldest][readPos[oldest]][sizeof(write_head)]; // outbuffer now points to the cap_head+pkt
	whead=(write_head*)datamem[oldest][readPos[oldest]];
	head=(cap_head*)outbuffer;
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
	memcpy(sendpointer[whead->consumer],head,(sizeof(cap_head)+head->caplen));// copy the packet to the sendbuffer
	sendpointer[whead->consumer]+=(sizeof(cap_head)+head->caplen); // Update the send pointer.
//	printf("head->caplen= %d\n",head->caplen);
	sendcount[whead->consumer]=sendcount[whead->consumer]+1;
	nextPDUlen=head->caplen;
	bzero(head,(sizeof(cap_head)+PKT_CAPSIZE));// Clear the memory where we read the packet. ALWAYS clear the full caplen.
	sentPkts++;
//	printf("ST: Oldest CI = %d -> Consumer %d\tcounter = %d \n",oldest,whead->consumer, sendcount[whead->consumer]);

//	printf("SENDER: Consumer[%d] -> push \n",whead->consumer);
//	printf("ST: %d / %d \n",(int)(sendpointer[whead->consumer]-sendptrref[whead->consumer]),maSendsize*(sizeof(cap_head)+PKT_CAPSIZE));	
	// If there are maSendsize packets in the sendbuffer[i] or the program is teminating send the buffer to its receiver. 
//	if(sendcount[whead->consumer]>(maSendsize-1) || terminateThreads>=1 ) { // This row assumes fixed PDU sizes
//	if((sendpointer[whead->consumer]-sendptrref[whead->consumer])>(maSendsize-1)*(sizeof(cap_head)+PKT_CAPSIZE) || terminateThreads>=1){ // This row assumes that a full size PDU should have enough space to be attached.
	if((sendpointer[whead->consumer]-sendptrref[whead->consumer])>(MAmtu-2*(sizeof(cap_head)+nextPDUlen)) || terminateThreads>=1){ // This row accounts for the fact that the consumer buffers only need extra space for one PDU of of the capture size for that particular filter. 
	  
	  printf("SendThread %d sending: %d > %d  ver %d.%d ",(int)pthread_self(), (int)(sendpointer[whead->consumer]-sendptrref[whead->consumer]),MAmtu-2*(sizeof(cap_head)+nextPDUlen),shead[whead->consumer]->version.major,shead[whead->consumer]->version.minor);
	  
	  for(k=0;k<ETH_ALEN;k++){// Copy the destination address from the ethernet header to the socket header.
	    socket_address.sll_addr[k]=ethhead[whead->consumer]->h_dest[k];// Set the destination address, defaults to 0x01:00:00:00:[i]
	  }
	  
/*
	  printf("ST: h_src = %02X:%02X:%02X:%02X:%02X:%02X  -->%02X:%02X:%02X:%02X:%02X:%02X \n",ethhead[whead->consumer]->h_source[0],ethhead[whead->consumer]->h_source[1],ethhead[whead->consumer]->h_source[2],ethhead[whead->consumer]->h_source[3],ethhead[whead->consumer]->h_source[4],ethhead[whead->consumer]->h_source[5],ethhead[whead->consumer]->h_dest[0],ethhead[whead->consumer]->h_dest[1],ethhead[whead->consumer]->h_dest[2],ethhead[whead->consumer]->h_dest[3],ethhead[whead->consumer]->h_dest[4],ethhead[whead->consumer]->h_dest[5]);
	  printf("sendcount[0]= %d sendcount[1] = %d \n ", sendcount[0],sendcount[1]);
*/

	  shead[whead->consumer]->nopkts=htons(sendcount[whead->consumer]); //maSendsize;
	  printf("dropCount[] = %d (g%d/m%d)",dropCount[whead->consumer],globalDropcount,memDropcount);
	  /*shead[whead->consumer]->losscounter=htons((globalDropcount+memDropcount)-dropCount[whead->consumer]); */
	  dropCount[whead->consumer]=globalDropcount+memDropcount;
	  printf("Consumer type = %d\n",consumerType[whead->consumer]);
	  switch(consumerType[whead->consumer]){
	    case 3:
	      printf("Sending TCP.\t");
	      written = write(MAsd[whead->consumer],
			      sendmem[whead->consumer]+sizeof(struct ethhdr)+sizeof(struct sendhead),
			      (sendpointer[whead->consumer]-sendptrref[whead->consumer]));
	      printf("Sent %d bytes.\n",written);
	      break;
	    case 2:
	      printf("Sending UDP .\t");
	      written = write(MAsd[whead->consumer],
			     sendmem[whead->consumer]+sizeof(struct ethhdr),
			      sizeof(struct sendhead)+(sendpointer[whead->consumer]-sendptrref[whead->consumer]));
	      printf("Sent %d bytes.\n",written);
	      break;
	    case 1:
	      if(ntohl((shead[whead->consumer]->sequencenr))%1==0){
		printf("Sending Ethernet.\t");
		printf("%02X:%02X:%02X:%02X:%02X:%02X-->%02X:%02X:%02X:%02X:%02X:%02X \t",ethhead[whead->consumer]->h_source[0],ethhead[whead->consumer]->h_source[1],ethhead[whead->consumer]->h_source[2],ethhead[whead->consumer]->h_source[3],ethhead[whead->consumer]->h_source[4],ethhead[whead->consumer]->h_source[5],ethhead[whead->consumer]->h_dest[0],ethhead[whead->consumer]->h_dest[1],ethhead[whead->consumer]->h_dest[2],ethhead[whead->consumer]->h_dest[3],ethhead[whead->consumer]->h_dest[4],ethhead[whead->consumer]->h_dest[5]);
		printf("seqnr = %04x \n", ntohl(shead[whead->consumer]->sequencenr));
	      }
	      written = sendto(MAsd[whead->consumer], 
			   sendmem[whead->consumer], 
			   sizeof(struct ethhdr)+sizeof(struct sendhead)+(sendpointer[whead->consumer]-sendptrref[whead->consumer]),//sizeof(struct sendhead)+sendcount[whead->consumer]*(sizeof(cap_head)+PKT_CAPSIZE)),
			   0,(struct sockaddr*)&socket_address, sizeof(socket_address));
//	      if(ntohl((shead[whead->consumer]->sequencenr))%1000==0){
//		printf("Sent %d bytes.\n",written);
//	      }
	      break;
	    case 0:
	      
	      if(ntohl((shead[whead->consumer]->sequencenr))%1==0){
		printf("Saving to file. (fd=%d)\n",MAsd[whead->consumer]);
	      }
	      written = write(MAsd[whead->consumer],sendmem[whead->consumer]+sizeof(struct ethhdr)+sizeof(struct sendhead),(sendpointer[whead->consumer]-sendptrref[whead->consumer]));
	      break;
	  }

	  printf("Sent.............\tPacket length = %d bytes, Eth %d, Send %d, Cap %d bytes\n.................\tSeqnr  = %04lx \t nopkts = %04x \t Losscount = %d\n.................\tsendto()-> %d\n\n",
		 sizeof(struct ethhdr)+sizeof(struct sendhead)+(sendpointer[whead->consumer]-sendptrref[whead->consumer]),//sizeof(struct sendhead)+sendcount[whead->consumer]*(sizeof(cap_head)+PKT_CAPSIZE),
		 sizeof(struct ethhdr), sizeof(struct sendhead),sizeof(struct cap_header), (unsigned long int)ntohl(shead[whead->consumer]->sequencenr), ntohs(shead[whead->consumer]->nopkts), -1 /*ntohs(shead[whead->consumer]->losscounter)*/,written);

	  if(written==-1) {
	    printf("sendto():\n");
	  }
	  printf("SEQNR: %04x\n",ntohs(shead[whead->consumer]->sequencenr));
//	  printf("Sent a measurement packet containing %d measurement packets.\n",sendcount[whead->consumer]);
	  //Update the sequence number.
	  shead[whead->consumer]->sequencenr=htonl(ntohl(shead[whead->consumer]->sequencenr)+1);
	  if(ntohl(shead[whead->consumer]->sequencenr)>0xFFFF){
	    shead[whead->consumer]->sequencenr=htonl(0);
	  }

	  writtenPkts += sendcount[whead->consumer];// Update the total number of sent pkts. 
	  sendcount[whead->consumer]=0;// Clear the number of packets in this sendbuffer[i]
	  //printf("ST: Send %d bytes. Total %d packets.\n",written, writtenPkts);
	  bzero(sendptrref[whead->consumer],(maSendsize*(sizeof(cap_head)+PKT_CAPSIZE))); //Clear the memory location, for the packet data. 
	  sendpointer[whead->consumer]=sendptrref[whead->consumer]; // Restore the pointer to the first spot where the next packet will be placed.
	  if((terminateThreads>=1)) // program is ending and all packets are sent
	    exitnr=1;
	}
      }//if(exitnr==0)
    }// End of while(exitnr==0) 
    // Flush all buffers..
    printf("Flushing sendbuffers.\n");
    for(i=0;i<CONSUMERS;i++){
      if(sendcount[i]>0){
	shead[i]=(struct sendhead*)(sendmem[i]+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
	shead[i]->flush=htons(1);
	printf("Consumer %d needs to be flushed, contains %d pkts\n",i, sendcount[i]);
	for(k=0;k<ETH_ALEN;k++){// Copy the destination address from the ethernet header to the socket header.
	  socket_address.sll_addr[k]=ethhead[whead->consumer]->h_dest[k];// Set the destination address, defaults to 0x01:00:00:00:[i]
	}
	switch(consumerType[i]){
	  case 3:
	    printf("Sending TCP.\t");
	    written = write(MAsd[i],
			    sendpointer[i],
			    (sendpointer[i]-sendptrref[i]));
	    break;
	  case 2:
	    printf("Sending UDP .\t");
	    written = write(MAsd[i],
			    sendmem[i]+sizeof(struct ethhdr),
			    sizeof(struct sendhead)+(sendpointer[i]-sendptrref[i]));
	    break;
	  case 1:
	    printf("Sending Ethernet.\t");
	    written=sendto(MAsd[i],
			   sendmem[i],
			   sizeof(struct ethhdr)+sizeof(struct sendhead)+(sendpointer[i]-sendptrref[i]),
			   0,
			   (struct sockaddr*)&socket_address,
			   sizeof(socket_address));
	    break;
	  case 0:
	    written = write(MAsd[i],sendmem[i]+sizeof(struct ethhdr)+sizeof(struct sendhead),(sendpointer[i]-sendptrref[i]));
	    break;
	}
	printf("Sent %d bytes.\n",written);
	if(written==-1) {
	  printf("sendto():");
	}
      }
    }
    //comes here when exitnr =1    
    printf("Sender Child %ld My work here is done .\n", pthread_self());
    return(NULL) ;
}
