/***************************************************************************
                          filter.c  -  description
                             -------------------
    begin                : Sat Mar 15 2003
    copyright            : (C) 2003 by Patrik Carlsson
    email                : patrik.carlsson@bth.se
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
  This function .......
 ***************************************************************************/
#include "capture.h"

#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <string.h>

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

#define TCP 4
#define UDP 3
#define IP 2
#define OTHER 1


int filter(char* CI, void *pkt, struct cap_header *head){
  int destination;
  int i;
  struct ethhdr *ether=0;
  struct ether_vlan_header *vlan=0;
  struct ip *ip_hdr=0;
  struct tcphdr *tcp=0;
  struct udphdr *udp=0;
  struct FPI *theRule;


//  struct FPI *aRule;

  
  int VLAN_PRESENT=0;


  if(noRules==0) {
    //    printf("CT[%ld]:%d Checking filter rules. NO RULES PRESENT ==> DROP.\n",pthread_self(),recvPkts);
    return(-1);
  } 
  //printf("CT[%ld]:%d Check filters ( %d):",pthread_self(), recvPkts,noRules);

  
  ether=(struct ethhdr*)pkt;
  destination=0;
  if(ntohs(ether->h_proto)==0x8100){
    vlan=(struct ether_vlan_header*)(pkt);
    VLAN_PRESENT=4;
  }

  
  if(VLAN_PRESENT==0) {
    if(ntohs(ether->h_proto)==ETHERTYPE_IP){
      ip_hdr=(struct ip*)(pkt+sizeof(struct ethhdr)+VLAN_PRESENT);
      //    printf("FL[%ld]Pkt(:IP:%04X)\n",pthread_self(),ip_hdr->ip_p);
    }
  } else {
    if(ntohs(vlan->h_proto)==ETHERTYPE_IP){
      ip_hdr=(struct ip*)(pkt+sizeof(struct ether_vlan_header));
      //    printf("FL[%ld]Pkt(:IP:%04X)\n",pthread_self(),ip_hdr->ip_p);
    }
  }

  destination=-1;

  theRule=myRules;
  for(i=0;i<noRules&&destination==-1;i++){
    if(i>0){// This is the second time around, we need to update the pointer.
      theRule=theRule->next;
    }
    //    printf("CT[%ld]:Checking rule [%d] index = %d.\n",pthread_self(),theRule->filter_id,theRule->index);
    if(theRule->index&512){ // We check the CI
      //printf("\t\tCI: (rule) %s  vs. %s (CI)\n", theRule->CI_ID, CI);
      if(strstr(CI,theRule->CI_ID)==NULL){ 
	//printf("FAIL.\n");
	continue; //  The rule was valid for another CI. 
      }
      //printf("MATCH.\n");
    }//CI
    if(theRule->index&256){ // We check the VLAN_TCI.
      //      printf("VLANTCI.");
      if(VLAN_PRESENT==0){
	//	printf("fail!\n");
	continue; // No VLAN present. Skip to next rule.
      }
      if((theRule->VLAN_TCI)!=(ntohs(vlan->vlan_tci)&theRule->VLAN_TCI_MASK)){
	//	printf("fail.\n");
	continue; // The VLAN_TCI fields does not match. Skip to next rule.
      }
    }//VLAN_TCI
    if(theRule->index&128){//Ethernet Type
      //printf("ETHTYPE %04x == %04x.",theRule->ETH_TYPE, (ntohs(ether->h_proto)&theRule->ETH_TYPE_MASK));
      if(VLAN_PRESENT==0) { // If No vlan is present the h_proto is at its normal place.
 	if((theRule->ETH_TYPE)!=(ntohs(ether->h_proto)&theRule->ETH_TYPE_MASK)){
	  //printf("fail\n");
	  continue; // The desired protocol&mask was not found in this frame. Next rule.
	}
      }
      if(VLAN_PRESENT==4) { // IF VLAN is present, we use the VLAN header to locate the h_proto field
	if((theRule->ETH_TYPE)!=(vlan->h_proto&theRule->ETH_TYPE_MASK)){
	  //	  printf("fail\n");
	  continue;// The desired protocol was not found, test next rule.
	}
      }
    }//Ethernet Type
    if(theRule->index&64) {//Ethernet Source
      //      printf("ETHSRC.");
      if(matchEth(theRule->ETH_SRC,theRule->ETH_SRC_MASK,ether->h_source)==0){
	//    printf("fail\n");
	continue;// The desired source&mask was not found. Next rule
      }
    }//Ethernet Source
    if(theRule->index&32) {//Ethernet Dest
      //      printf("ETHDST.");
      if(matchEth(theRule->ETH_DST,theRule->ETH_DST_MASK, ether->h_dest)==0){
	//	printf("fail\n");
	continue;// The desired destination&mask was not found. Next rule
      }
    }//Ethernet Destination
    if(theRule->index&16) { // IP Protocol
      if(ip_hdr==0){
	//printf("fail\n");
	continue;
      }
      //printf("\t\tIP_PROTOL = %d.", ip_hdr->ip_p);
      if(theRule->IP_PROTO!=ip_hdr->ip_p){ 
	//printf("FAIL\n");
	continue; // The desired transport protocol was not found. Next Rule
      }
      //printf("MATCH\n");
      if(theRule->IP_PROTO==IPPROTO_UDP){
	//printf("UDP payload..\n");
	udp=(struct udphdr*)(pkt+sizeof(struct ethhdr)+VLAN_PRESENT+4*(ip_hdr->ip_hl));
      }
      if(theRule->IP_PROTO==IPPROTO_TCP){
	//printf("TCP payload.. \n");
	tcp=(struct tcphdr*)(pkt+sizeof(struct ethhdr)+VLAN_PRESENT+4*(ip_hdr->ip_hl));
      }
    }
    if(theRule->index&8){// IP Source
      //printf("IPSRC.");
      if(ip_hdr==0){
	//printf("fail(NO IPHDR)\n");
	continue;
      } 
      //printf("IP.src = %s ", inet_ntoa(ip_hdr->ip_src));
      if(inet_addr(theRule->IP_SRC)!=(ip_hdr->ip_src.s_addr&inet_addr(theRule->IP_SRC_MASK))){
	//printf("fail\n");
	continue; // The desired source address was not found.
      }
/*
  unsigned char *ptr=(unsigned char *)(ip_hdr);
  printf("privacy.%s --> ", inet_ntoa(ip_hdr->ip_src));
      printf("\npkt            = %p \n",pkt);
      printf("ip_hdr         = %p \n",ip_hdr);
      printf("ip_hdr->src    = %p \n",ptr);
      printf("Addr = %d \n",(ptr[12]));
      printf("     = %d \n",(ptr[13]));
      printf("     = %d \n",(ptr[14]));
      printf("     = %d \n",(ptr[15]));
      printf("     = %d \n",p);
      printf("     = %d \n",p);
      //unsigned char p=ptr[15];
      //p= p << ENCRYPT | ( p >> (8-ENCRYPT));
      printf("%s rotated\n",inet_ntoa(ip_hdr->ip_src));
*/

      //printf(" match\n");
    }//IP Source
    if(theRule->index&4){// IP Dest
      //printf("IPDST.");
      if(ip_hdr==0){
	//printf("fail(NO IPHDR)\n");
	continue;
      }
      //printf("IP.dst = %s ", inet_ntoa(ip_hdr->ip_dst));
      if(inet_addr(theRule->IP_DST)!=(ip_hdr->ip_dst.s_addr&inet_addr(theRule->IP_DST_MASK))){
	//printf("fail\n");
	continue; // The desired destination address was not found.
      }
      //printf(" match\n");
    }//IP Dest
    if(theRule->index&2){// Transport Source Port
      //printf("SRCPRT.");
      if(ip_hdr==0){
	//printf("fail(NO IPHDR)\n");
	continue;
      }

      if(udp!=0){//Payload is not UDP
	//printf("UDP.port = %d ", ntohs(udp->source));
	if(theRule->SRC_PORT!=(ntohs(udp->source)&theRule->SRC_PORT_MASK)){
	  //printf("fail\n");
	  continue;//Source port does not match, next rule
	}
	//printf(" match\n");
      }
      if(tcp!=0){//Payload is TCP
	//printf("TCP.port = %d", ntohs(tcp->source));
	if(theRule->SRC_PORT!=(ntohs(tcp->source)&theRule->SRC_PORT_MASK)){
	  //printf("fail\n");
	  continue;//Source port does not match, next rule
	}
	//printf(" match\n");
      }
      if(tcp==0 && udp==0) {
	// Unknown transport protocol.
	//	printf("fail(UNKNOWN TP)\n");
	continue;
      }
      
    }// Transport Source Port
    if(theRule->index&1){// Transport Dest Port
      //printf("DSTPRT.");
      if(ip_hdr==0){
	//	printf("fail(NO IPHDR).\n");
	continue;
      }
      if(udp!=0){//Payload is UDP
	//printf("UDP.port = %d ", ntohs(udp->dest));
	if(theRule->DST_PORT!=(ntohs(udp->dest)&theRule->DST_PORT_MASK)){
	  //printf("fail\n");
	  continue;//Source port does not match, next rule
	}
	//printf(" match\n");
      }
      if(tcp!=0){//Payload is TCP
	//printf("TCP.port = %d ", ntohs(tcp->dest));
	if(theRule->DST_PORT!=(ntohs(tcp->dest)&theRule->DST_PORT_MASK)){
	  //printf("fail\n");
	  continue;//Source port does not match, next rule
	}
	//printf(" match\n");
      }
      if(tcp==0 && udp==0) {
	// Unknown transport protocol.
	//printf("fail(UNKNOWN TP)\n");
	continue;
      }
    }// Transport Dest Port
    //IF we end up here, THEN the PACKET MATCHES THIS RULE!!!
    destination=theRule->consumer;
//    printf("FL[%ld] MATCH RULE %d, %d bytes -> Consumer %d\n",pthread_self(),theRule->filter_id, theRule->CAPLEN,destination);
    head->caplen=theRule->CAPLEN;
  }//FOR(i=0;i<noRules&&destination==0;i++)
  // printf("filter = %d\n", destination);

  if(ip_hdr!=0 && ENCRYPT>0){ // It is atleast a IP header.
    unsigned char *ptr=(unsigned char *)(ip_hdr);
    ptr[15]=ptr[15] << ENCRYPT | ( ptr[15] >> (8-ENCRYPT)); // Encrypt Sender
    ptr[19]=ptr[19] << ENCRYPT | ( ptr[19] >> (8-ENCRYPT)); // Encrypt Destination
  }

  return destination;  
}

int matchEth(char desired[6],char mask[6], char net[6]){
  int i;
  for(i=0;i<6;i++){
    if((net[i]&mask[i])!=desired[i]){
       break;
    }
  }
  if(i==6)
    return(1);
  return(0);
}

/*
  This function adds a filter to the end of the list.
*/
int addFilter(struct FPI *newRule){
  struct FPI *pointer1=0;
  struct FPI *pointer2=0;
  int i,k;
  long ret = 0;
  newRule->next=0; // Make sure that the rule does not point to some strange place.
  pointer1=myRules;
  printf("addFilter\n");
  if(pointer1==0){ // First rule
    newRule->consumer=0;

    const char* address = newRule->DESTADDR;
    if ( newRule->TYPE == 1 ){
      /* address is not passed as "01:00:00:00:00:00", but as actual memory with
       * bytes 01 00 00 ... createstream expects a string. */
      address = hexdump_address(address);
    }

    if ( (ret=createstream(&MAsd[0].stream, address, newRule->TYPE, MAnic, MAMPid, "caputils 0.7 test MP")) != 0 ){
      fprintf(stderr, "createstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
      exit(1);
    }

    MAsd[0].want_sendhead = newRule->TYPE != 0; /* capfiles shouldn't contain sendheader */

    /* switch(newRule->TYPE){ */
    /*   case 0:// File */
    /* 	MAsd[0]=file_connect(newRule->DESTADDR); */
    /* 	break; */
    /*   case 1:// Ethernet */
    /* 	MAsd[0]=ethernet_connect(); */
    /* 	break; */
    /*   case 2:// UDP */
    /* 	MAsd[0]=udp_connect(newRule->DESTADDR,newRule->DESTPORT); */
    /* 	break; */
    /*   case 3:// TCP */
    /* 	MAsd[0]=tcp_connect(newRule->DESTADDR,newRule->DESTPORT); */
    /* 	break; */
    /* } */
    MAsd[0].status=1;
    myRules=newRule;
    noRules++;
    printf("\tThis is the first rule.\n");
    struct ethhdr *ethhead; // pointer to ethernet header
    ethhead= (struct ethhdr*)sendmem[newRule->consumer];
    printf("\tDestination ");
    switch(newRule->TYPE==1){
      case 3:
      case 2:
	printf(" IP ADDR: %s PORT: %d", newRule->DESTADDR, newRule->DESTPORT);
	break;
      case 1:
	printf(" ETH ADDR : ");
	for(i=0;i<ETH_ALEN;i++){
	  ethhead->h_dest[i]=newRule->DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
	  printf("%02X:",ethhead->h_dest[i]);
	}
	break;
      case 0:
	printf(" file : %s", newRule->DESTADDR);
	break;
    }
    
    printf("\n");
    return(1);
  }
  /* Lets find a free consumer */
  i=0;
  while( MAsd[i].status==1 && i<CONSUMERS){
    i++;
  }
  
  if(i>=CONSUMERS) { // Problems, NO free consumers. Bail out! 
    printf("\tNO FREE CONSUMERS BAILOUT!!%d-%d\n",i,CONSUMERS);
    return(0);
  }
  
  printf("CTRL: ADD FILTER TO CONSUMER %d \n",i);
  newRule->consumer=i;
  MAsd[i].status=1;
  MAsd[i].dropCount=globalDropcount+memDropcount;
  struct ethhdr *ethhead; // pointer to ethernet header
  ethhead= (struct ethhdr*)sendmem[newRule->consumer];

  if ( (ret=createstream(&MAsd[i].stream, newRule->DESTADDR, newRule->TYPE, NULL, MAMPid, "caputils 0.7 test MP")) != 0 ){
    fprintf(stderr, "openstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
    exit(1);
  }

  printf("\tDestination ");
  switch(newRule->TYPE){
    case 3:
    case 2:
      printf(" IP ADDR: %s PORT: %d", newRule->DESTADDR, newRule->DESTPORT);
      break;
    case 1:
      printf(" ETH ADDR : ");
      for(k=0;k<ETH_ALEN;k++){
	ethhead->h_dest[k]=newRule->DESTADDR[k];   // Set the destination address, defaults to 0x01:00:00:00:[i]
	printf("%02X:",ethhead->h_dest[k]);
      }
      break;
    case 0:
      printf(" file : %s", newRule->DESTADDR);
      break;
  }
  
  printf("\n");
  printf("Locating the position!:\n");
  printf("myRules =%p --> %p\n", myRules, myRules->next);
  printf("newRule = %p, pointer1 = %p, pointer2 = %p\n", newRule, pointer1, pointer2);
  while(pointer1->filter_id<newRule->filter_id && pointer1->next != 0 ){
    pointer2=pointer1;
    pointer1=pointer1->next;
  }
  printf("Got location? \n");
  printf("newRule = %p, pointer1 = %p, pointer2 = %p\n", newRule, pointer1, pointer2);
  if(pointer2!=0){ 
    printf("-->next = %p,  -->next = %p,  -->next = %p\n", newRule->next, pointer1->next, pointer2->next);      
  } else {
    printf("-->next = %p,  -->next = %p,  -->next = N/A\n", newRule->next, pointer1->next);      
  }
  // We leave this while loop on two cases, 1) filter_id>=new id. 2) this is the last rule.
  if(pointer1->next == 0) {
    if(pointer1->filter_id<newRule->filter_id) { // Append to end of list
      printf("Append to end of list.\n");
      pointer1->next=newRule;
      noRules++;// Update the number of rules. 
      return(1);
    }
    if(pointer1->filter_id>newRule->filter_id){ // Insert between last and previous.
      printf("Insert inbetween.\n");
      printf("newRule = %p, pointer1 = %p, pointer2 = %p\n", newRule, pointer1, pointer2);
      if(pointer2!=0){ 
	printf("-->next = %p,  -->next = %p,  -->next = %p\n", newRule->next, pointer1->next, pointer2->next);      
      } else {
	printf("-->next = %p,  -->next = %p,  -->next = N/A\n", newRule->next, pointer1->next);      
      }
      printf("myRules =%p --> %p\n", myRules, myRules->next);
      newRule->next=pointer1;
      if(pointer2==0){
	printf("New rule is placed in front of list.\n");
	myRules=newRule;
      } else {
	pointer2->next=newRule;
      }
      printf("-------------------------------\n");
      printf("newRule = %p, pointer1 = %p, pointer2 = %p\n", newRule, pointer1, pointer2);
      if(pointer2!=0){ 
	printf("-->next = %p,  -->next = %p,  -->next = %p\n", newRule->next, pointer1->next, pointer2->next);      
      } else {
	printf("-->next = %p,  -->next = %p,  -->next = N/A\n", newRule->next, pointer1->next);      
      }
      printf("myRules =%p --> %p\n", myRules, myRules->next);
      noRules++;
      return(1);
    }
    if(pointer1->filter_id==newRule->filter_id){ // They are equal.. Problems..
      printf("\tProblem, new rule has the same filter_id as the last rule..\n");
      newRule->next=pointer1;
      pointer2->next=newRule;
      noRules++;
      return(1);
    }
  }
  if(pointer1->filter_id>newRule->filter_id){// Insert inbetween p2 and p1.
    printf("p2 and p1\n");
    printf("pointer1->filter_id = %d\n", pointer1->filter_id);
    printf(" newRule->filter_id = %d\n", newRule->filter_id);
    newRule->next=pointer1;
    if(myRules==pointer1){
      printf("New rule is placed first.\n");
      myRules=newRule;
    } else {
      pointer2->next=newRule;
    }

    noRules++;
    return(1);
  }    
  if(pointer1->filter_id==newRule->filter_id){// Insert inbetween p2 and p1., PROBLEM. filter_id are identical
    printf("\tProblem, new rule has the same filter_id as the last rule..\n");
    newRule->next=pointer1;
    pointer2->next=newRule;
    noRules++;
    return(1);
  }    

  return(1);
}


/*
 This function finds a filter that matched the filter_id, and removes it.
*/
int delFilter(int filter_id){
  int seeked=filter_id;
  struct FPI *pointer1,*pointer2;
  pointer1=pointer2=0;
  if(myRules==0){
    // No Rules present, ERROR..
    return(0);
  }
  pointer1=myRules;
  if(pointer1->filter_id==seeked){ // Found the desired filter..It was first.
    myRules=pointer1->next;// Update the basepointer-> the next rule
    flushSendBuffer(pointer1->consumer);
    free(pointer1);  // Release the old pointer. 
    noRules--; // Update the amount of rules.
    return(1);
  }
  while(pointer1->filter_id!=seeked && pointer1->next != 0) {
    pointer2=pointer1;
    pointer1=pointer1->next;
  }
  // Two reasons to leave while loop. 1) pointer1->filter_id == seeked, 2) pointer1->next == 0
  if(pointer1->filter_id==seeked){ // We found it.
    pointer2->next = pointer1->next;// Make sure that the old element is not in the list anymore.
    flushSendBuffer(pointer1->consumer);
    free(pointer1);              // relase the memory allocated by the old rule.
    noRules--;
    return(1);
  }
  // We didnt find it... (if we did at the last location, the previous if would catch it.
  return(0);
}

/*
 Flush the sendbuffer.
*/
void flushSendBuffer(int index){
  printf("CTRL: DEL FILTER TO CONSUMER %d \n",index);
  int i,written;
  unsigned char DESTADDR[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  i=written=0;

  /** @todo mostly dup of flushBuffer */
  
  struct consumer* con = &MAsd[i];
  
  /* no consumer */
  if ( !con ){
    return;
  }

  /* no packages to send */
  if ( con->sendcount == 0 ){
    return;
  }
  

  con->shead=(struct sendhead*)(sendmem[index]+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
  con->shead->flush=htons(1);

  printf("\tConsumer %d needs to be flushed, contains %d pkts\n",i, con->sendcount);
  //for(i=0;i<ETH_ALEN;i++){// Copy the destination address from the ethernet header to the socket header.
  //  socket_address.sll_addr[i]=ethhead[index]->h_dest[i];// Set the destination address, defaults to 0x01:00:00:00:[i]
  //}
  memcpy(socket_address.sll_addr, con->ethhead->h_dest, ETH_ALEN);

  con->shead->nopkts=con->sendcount;

  size_t len = con->sendpointer - con->sendptrref;
  con->stream->write(con->stream, con->sendptrref, len);

  /* switch(consumerType[index]){ */
  /* case 3: */
  /*   written = write(MAsd[index], */
  /* 		    sendpointer[index], */
  /* 		    (sendpointer[index]-sendptrref[index])); */
  /*   break; */
  /* case 2: */
  /*   written=write(MAsd[index], */
  /* 		  sendmem[index]+sizeof(struct ethhdr), */
  /* 		  (sizeof(struct sendhead)+(sendpointer[index]-sendptrref[index]))); */
  /*   break; */
  /* case 1: */
  /*   written=sendto(MAsd[index],sendmem[index],(sizeof(struct ethhdr)+sizeof(struct sendhead)+sendcount[index]*(sizeof(cap_head)+PKT_CAPSIZE)), 0,(struct sockaddr*)&socket_address, sizeof(socket_address)); */
  /*   printf("\tST: sent %d bytes\n\tST: MAsd[] = %d len = %d\n\tST: sockaddr.sll_protocol = %x\n\tST: sockaddr.sll_ifindex = %d\n\tST: seqnr  = %04x \t nopkts = %04x \n",written,MAsd[index],sizeof(struct sendhead)+sendcount[index]*(sizeof(cap_head)+PKT_CAPSIZE),ntohs(socket_address.sll_protocol),socket_address.sll_ifindex,ntohs(shead[index]->sequencenr),shead[index]->nopkts); */
  /*   break; */
  /* case 0: */
  /* 	break; */
  /* } */

  printf("Sent %d bytes.\n",written);
  if(written==-1) {
    printf("sendto():");
  }

  long ret = 0;
  if ( (ret=closestream(con->stream)) != 0 ){
    fprintf(stderr, "closestream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
  }
  con->stream = NULL;

  /* Reinitialize ethernet and sendheader */
  //for(i=0;i<ETH_ALEN;i++){
  //  ethhead[index]->h_dest[i]=DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
  //}
  memcpy(con->ethhead->h_dest, DESTADDR, ETH_ALEN);

  con->ethhead->h_dest[5]=index;   // Set the destination address, defaults to 0x01:00:00:00:[i]
  con->shead->sequencenr=htonl(0x000);
  con->shead->nopkts=htons(0);			  // Initialize the number of packet to zero
  con->shead->flush=htons(0);			  // Make sure that the flush indicator is zero!
  con->shead->version.major=CAPUTILS_VERSION_MAJOR; // Specify the file format used, major number
  con->shead->version.minor=CAPUTILS_VERSION_MINOR; // Specify the file format used, minor number
  /*con->shead->losscounter=htons(0); */
  con->sendpointer=sendmem[index]+sizeof(struct ethhdr)+sizeof(struct sendhead);            // Set sendpointer to first place in sendmem where the packets will be stored.
  con->sendptrref=con->sendpointer;          // Grab a copy of the pointer, simplifies treatment when we sent the packets.
  con->sendcount=0;
  con->status=0;
  
  bzero(con->sendpointer, maxSENDSIZE*(sizeof(cap_head)+PKT_CAPSIZE)); // Clear memory.
  return;
}

/*
 This function finds a filter and changes it.
A change will NOT allow a change of consumer, new mutlicast address is OK ,but not recommended..
*/
int changeFilter(struct FPI *newRule){
  int seeked=newRule->filter_id;
  struct FPI *pointer1,*pointer2;
  pointer1=pointer2=0;
  struct ethhdr *ethhead;
  int i;

  printf("CTRL: CHANGE RULE.\n");
  if(myRules==0){
    // No Rules present, ERROR..
    return(0);
    
  }
  pointer1=myRules;
  if(pointer1->filter_id==seeked){ // Found the desired filter..It was first.fil
    newRule->consumer=pointer1->consumer;
    newRule->next=pointer1->next; // Make sure that the new rule points to the next.
    myRules=newRule; // Update the basepointer-> the new rule.
    free(pointer1);  // Release the old pointer. 

    ethhead= (struct ethhdr*)sendmem[newRule->consumer];
    printf("\tDestination address => ");
    for(i=0;i<ETH_ALEN;i++){
      ethhead->h_dest[i]=newRule->DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
      printf("%02X:",ethhead->h_dest[i]);
    }
    printf("\n");
    return(1);
  }

  while(pointer1->filter_id!=seeked && pointer1->next != 0) {
    pointer2=pointer1;
    pointer1=pointer1->next;
  }
  // Two reasons to leave while loop. 1) pointer1->filter_id == seeked, 2) pointer1->next == 0
  if(pointer1->filter_id==seeked){ // We found it.
    newRule->consumer=pointer1->consumer;
    newRule->next=pointer1->next;//Make sure that the new rule points to the next.
    pointer2->next=newRule;      // Update the previous rule so it points to the new.
    free(pointer1);              // relase the memory allocated by the old rule.

    ethhead= (struct ethhdr*)sendmem[newRule->consumer];
    printf("\tDestination address => ");
    for(i=0;i<ETH_ALEN;i++){
      ethhead->h_dest[i]=newRule->DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
      printf("%02X:",ethhead->h_dest[i]);
    }
    printf("\n");

    return(1);
  }
  // We didnt find it... (if we did at the last location, the previous if would catch it.
    return(0);

} 


void printFilters(void){
  struct FPI *pointer;

  if(myRules==0){
    printf("NO RULES\n");
  }
  
  pointer=myRules;
  while(pointer->next != 0){
    printFilter(pointer);
    pointer=pointer->next;
  }
  printFilter(pointer);
}

int printMysqlFilter(char *array,char *id, int seeked){
  struct FPI *F;
  if(myRules==0){
    // No Rules present, ERROR..
    sprintf(array, "INSERT INFO %s_filterlistverify SET filter_id=%d, comment='NO RULES PRESENT'",id,seeked);
    return(0);
  }
  F=myRules;
  if(F->filter_id!=seeked){ // The first isn't the seeked one
    while(F->filter_id!=seeked && F->next != 0) {
      F=F->next;
    }
    if(F->filter_id!=seeked){
      // We didnt find it. 
      sprintf(array, "INSERT INFO %s_filterlistverify SET filter_id=%d, comment='RULES NOT FOUND PRESENT'",id,seeked);
      return(0);
    }
  }
  //  printf("Found it, now we create the query.. %d\n",F->filter_id);
  sprintf(array,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',ETH_SRC_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', DESTADDR='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', type ='%d', caplen='%d' consumer='%d'",
	  id,F->filter_id,F->index,F->CI_ID,F->VLAN_TCI,F->VLAN_TCI_MASK,
	  F->ETH_TYPE,F->ETH_TYPE_MASK, 
	  (unsigned char)(F->ETH_SRC[0]),(unsigned char)(F->ETH_SRC[1]),(unsigned char)(F->ETH_SRC[2]),(unsigned char)(F->ETH_SRC[3]),(unsigned char)(F->ETH_SRC[4]),(unsigned char)(F->ETH_SRC[5]),
	  (unsigned char)(F->ETH_SRC_MASK[0]),(unsigned char)(F->ETH_SRC_MASK[1]),(unsigned char)(F->ETH_SRC_MASK[2]),(unsigned char)(F->ETH_SRC_MASK[3]),(unsigned char)(F->ETH_SRC_MASK[4]),(unsigned char)(F->ETH_SRC_MASK[5]),
	  
	  (unsigned char)(F->ETH_DST[0]),(unsigned char)(F->ETH_DST[1]),(unsigned char)(F->ETH_DST[2]),(unsigned char)(F->ETH_DST[3]),(unsigned char)(F->ETH_DST[4]),(unsigned char)(F->ETH_DST[5]),
	  (unsigned char)(F->ETH_DST_MASK[0]),(unsigned char)(F->ETH_DST_MASK[1]),(unsigned char)(F->ETH_DST_MASK[2]),(unsigned char)(F->ETH_DST_MASK[3]),(unsigned char)(F->ETH_DST_MASK[4]),(unsigned char)(F->ETH_DST_MASK[5]),
	  F->IP_PROTO,
	  F->IP_SRC,F->IP_SRC_MASK,
	  F->IP_DST,F->IP_DST_MASK,
	  F->SRC_PORT,F->SRC_PORT_MASK,
	  F->DST_PORT,F->DST_PORT_MASK,
	  (unsigned char)(F->DESTADDR[0]),(unsigned char)(F->DESTADDR[1]),(unsigned char)(F->DESTADDR[2]),(unsigned char)(F->DESTADDR[3]),(unsigned char)(F->DESTADDR[4]),(unsigned char)(F->DESTADDR[5]),F->TYPE,F->CAPLEN,
	  F->consumer);

  return(1);
}

void printFilter(struct FPI *F){
  printf("CTRL PRINT FILTER\n");
  printf("filter_id    :%d\n",F->filter_id);
  printf("consumer     :%d\n",F->consumer);
  switch(F->TYPE){
    case 3:
    case 2:
      printf("DESTADDRESS  :%s TYPE : %d\n",F->DESTADDR, F->TYPE);
      printf("DESTPORT     :%d \n",F->DESTPORT);
      break;
    case 1:
      printf("DESTADDRESS  :%02X:%02X:%02X:%02X:%02X:%02X  TYPE    :%d\n",F->DESTADDR[0],F->DESTADDR[1],F->DESTADDR[2],F->DESTADDR[3],F->DESTADDR[4],F->DESTADDR[5], F->TYPE);
      break;
    case 0:
      printf("DESTFILE     :%s TYPE %d \n",F->DESTADDR, F->TYPE);
      break;
  }
  printf("CAPLEN       :%d\n",F->CAPLEN);
  printf("index        :%d\n",F->index);
  printf("CI_ID        :");
  if(F->index&512)
    printf("%s\n",F->CI_ID);
  else 
    printf("NULL\n");
  
  printf("VLAN_TCI     :");
  if(F->index&256){
    printf("%d\n",F->VLAN_TCI);
    printf("VLAN_TCI_MASK:%d\n",F->VLAN_TCI_MASK);
  }  else{
    printf("NULL\n");
    printf("VLAN_TCI_MASK:NULL\n");
  }

  printf("ETH_TYPE     :");
  if(F->index&128){
    printf("%d\n",F->ETH_TYPE);
    printf("ETH_TYPE_MASK: %d\n",F->ETH_TYPE_MASK);
  }  else {
    printf("NULL\n");
    printf("ETH_TYPE_MASK:NULL\n");
  }
  
  printf("ETH_SRC      :");
  if(F->index&64){
    printf("%s\n",hexdump_address(F->ETH_SRC));
    printf("ETH_SRC_MASK :%s\n",hexdump_address(F->ETH_SRC_MASK));
  } else {
    printf("NULL\n");
    printf("ETH_SRC_MASK:NULL\n");
  }

  printf("ETH_DST      :");
  if(F->index&32){
    printf("%s\n",hexdump_address(F->ETH_DST));
    printf("ETH_DST_MASK:%s\n",hexdump_address(F->ETH_DST_MASK));
  } else {
    printf("NULL\n");
    printf("ETH_DST_MASK :NULL\n");
  }
  
  printf("IP_PROTO     :");
  if(F->index&16)
    printf("%d\n",F->IP_PROTO);
  else
    printf("NULL\n");

  printf("IP_SRC       :");
  if(F->index&8){
    printf("%s\n",F->IP_SRC);
    printf("IP_SRC_MASK  :%s\n",F->IP_SRC_MASK);
  } else {
    printf("NULL\n");
    printf("IP_SRC_MASK:NULL\n");
  }

  printf("IP_DST       :");
  if(F->index&4){
    printf("%s\n",F->IP_DST);
    printf("IP_DST_MASK  :%s\n",F->IP_DST_MASK);
  } else {
    printf("NULL\n");
    printf("IP_DST_MASK:NULL\n");
  }

  printf("PORT_SRC     :");
  if(F->index&2){
    printf("%d\n",F->SRC_PORT);
    printf("PORT_SRC_MASK:%d\n",F->SRC_PORT_MASK);
  } else {
    printf("NULL\n");
    printf("PORT_SRC_MASK:NULL\n");
  }

  printf("PORT_DST     :");
  if(F->index&1){
    printf("%d\n",F->DST_PORT);
    printf("PORT_DST_MASK:%d\n",F->DST_PORT_MASK);
  } else {
    printf("NULL\n");
    printf("PORT_DST_MASK:NULL\n");
  }
  

}
