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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "filter.h"
#include "log.h"

#include <libmarc/filter.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <string.h>
#include <linux/if.h>
// 
//#define STPBRIDGES 0x0026
//#define CDPVTP 0x016E
// 
//#define TCP 4
//#define UDP 3
//#define IP 2
//#define OTHER 1

struct Haystack {
  const char* CI;
  const char* pkt;
  const struct ethhdr* ether;
  const struct ether_vlan_header* vlan;
  struct ip* ip_hdr;
};

static int matchEth(const unsigned char d[], const unsigned char m[], const unsigned char n[]);
static void stop_consumer(struct consumer* con);

static char hex_string[IFHWADDRLEN * 3] = "00:00:00:00:00:00";
static char* hexdump_address (const unsigned char address[IFHWADDRLEN]){
  int i;

  for (i = 0; i < IFHWADDRLEN - 1; i++) {
    sprintf (hex_string + 3*i, "%2.2X:", (unsigned char) address[i]);
  }  
  sprintf (hex_string + 15, "%2.2X", (unsigned char) address[i]);
  return (hex_string);
}

/**
 * Try to match filter against haystack.
 * @return 1 if match, 0 if not.
 */
int filter_match(const struct Filter* filter, const struct Haystack* haystack) {
  const struct ethhdr* ether = haystack->ether;
  const struct ether_vlan_header* vlan = haystack->vlan;
  struct ip* ip_hdr = haystack->ip_hdr;
  struct tcphdr* tcp = NULL;
  struct udphdr* udp = NULL;
  const size_t vlan_offset = haystack->vlan ? 4 : 0;

  /* Capture Interface */
  if ( filter->index & FILTER_CI ){
    if( strstr(haystack->CI, filter->CI_ID) == NULL ){ 
      return 0;
    }
  }

  /*  VLAN TCI (Tag Control Information) */
  if ( filter->index & FILTER_VLAN ){
    if( !haystack->vlan ){
      return 0;
    }

    const uint16_t tci = ntohs(haystack->vlan->vlan_tci) & filter->VLAN_TCI_MASK;
    if ( filter->VLAN_TCI != tci ){
      return 0;
    }
  }

  /* Ethernet type */
  if ( filter->index & FILTER_ETH_TYPE ){
    uint8_t h_proto;

    /* If No vlan is present the h_proto is at its normal place. */
    if ( haystack->vlan == NULL ) {
      h_proto = ntohs(ether->h_proto) & filter->ETH_TYPE_MASK;
    } else {
      h_proto = ntohs(vlan->h_proto) & filter->ETH_TYPE_MASK;
    }

    if( filter->ETH_TYPE != h_proto ){
      return 0;
    }
  }

  /* Ethernet Source */
  if ( filter->index & FILTER_ETH_SRC ) {
    /** @todo shouldn't VLAN_PRESENT be considered */
    if ( matchEth(filter->ETH_SRC.ether_addr_octet, filter->ETH_SRC_MASK.ether_addr_octet, ether->h_source) == 0 ){
      return 0;
    }
  }

  /* Ethernet Destination */
  if( filter->index & FILTER_ETH_DST ) {
    /** @todo shouldn't VLAN_PRESENT be considered */
    if ( matchEth(filter->ETH_DST.ether_addr_octet, filter->ETH_DST_MASK.ether_addr_octet, ether->h_dest) == 0 ){
      return 0;
    }
  }

  /* IP Protocol */
  if ( filter->index & FILTER_IP_PROTO ) {
    /* not an IP-packet */
    if ( ip_hdr==0 ){
      return 0;
    }

    if ( filter->IP_PROTO != ip_hdr->ip_p ){ 
      return 0;
    }

    if( filter->IP_PROTO == IPPROTO_UDP ){
      udp = (struct udphdr*)(haystack->pkt+sizeof(struct ethhdr) + vlan_offset + 4*(ip_hdr->ip_hl));
    }

    if( filter->IP_PROTO == IPPROTO_TCP ){
      tcp = (struct tcphdr*)(haystack->pkt+sizeof(struct ethhdr) + vlan_offset + 4*(ip_hdr->ip_hl));
    }
  }

  /* IP source address */
  if ( filter->index & FILTER_IP_SRC ){
    if ( ip_hdr==0 ){
      return 0;
    }

    const in_addr_t src = ip_hdr->ip_src.s_addr & inet_addr(filter->IP_SRC_MASK);

    if ( inet_addr(filter->IP_SRC) != src ){
      return 0;
    }
  }

  /* IP destination address */
  if ( filter->index & FILTER_IP_DST ){
    if ( ip_hdr==0 ){
      return 0;
    }

    const in_addr_t dst = ip_hdr->ip_dst.s_addr & inet_addr(filter->IP_DST_MASK);

    if ( inet_addr(filter->IP_DST) != dst ){
      return 0;
    }
  }

  /* Transport source port */
  if ( filter->index & FILTER_SRC_PORT ){
    if ( ip_hdr==0 ){
      return 0;
    }

    uint16_t port;
    if ( udp != 0 ){ /* UDP */
      port = ntohs(udp->source) & filter->SRC_PORT_MASK;
    } else if ( tcp != 0 ){ /* TCP */
      port = ntohs(tcp->source) & filter->SRC_PORT_MASK;
    } else {
      return 0; /* unhandled transport protocol */
    }

    if ( filter->SRC_PORT != port ){
      return 0;
    }
  }

  /* Transport destionation port */
  if ( filter->index & FILTER_DST_PORT ){
    if ( ip_hdr==0 ){
      return 0;
    }

    uint16_t port;
    if ( udp != 0 ){ /* UDP */
      port = ntohs(udp->dest) & filter->DST_PORT_MASK;
    } else if ( tcp != 0 ){ /* TCP */
      port = ntohs(tcp->dest) & filter->DST_PORT_MASK;
    } else {
      return 0; /* unhandled transport protocol */
    }

    if ( filter->DST_PORT != port ){
      return 0;
    }
  }

  return 1;
}

int filter(const char* CI, const void *pkt, struct cap_header *head){
  if ( noRules==0 ) {
    return -1;
  }

  struct Haystack haystack;
  haystack.CI = CI;
  haystack.ether = (struct ethhdr*)pkt;
  haystack.vlan = NULL;
  haystack.ip_hdr = NULL;

  /* setup vlan header */
  if(ntohs(haystack.ether->h_proto)==0x8100){
    haystack.vlan = (struct ether_vlan_header*)(pkt);
  }

  /* setup IP header */
  if ( haystack.vlan == NULL ) {
    if(ntohs(haystack.ether->h_proto) == ETHERTYPE_IP){
      haystack.ip_hdr=(struct ip*)(pkt+sizeof(struct ethhdr));
    }
  } else {
    if(ntohs(haystack.vlan->h_proto) == ETHERTYPE_IP){
      haystack.ip_hdr=(struct ip*)(pkt+sizeof(struct ether_vlan_header));
    }
  }

  int destination = -1;

  struct FPI* rule = myRules;
  while ( rule ){
    const struct Filter* filter = &rule->filter;

    if ( filter_match(filter, &haystack) == 1 ){
      /* packet matches */
      destination = filter->consumer;
      head->caplen = filter->CAPLEN;
      break;
    }

    /* try next rule */
    rule = rule->next;
  }

  if( haystack.ip_hdr !=0 && ENCRYPT>0){ // It is atleast a IP header.
    unsigned char *ptr=(unsigned char *)(haystack.ip_hdr);
    ptr[15]=ptr[15] << ENCRYPT | ( ptr[15] >> (8-ENCRYPT)); // Encrypt Sender
    ptr[19]=ptr[19] << ENCRYPT | ( ptr[19] >> (8-ENCRYPT)); // Encrypt Destination
  }

  return destination;  
}

static int matchEth(const unsigned char desired[6], const unsigned char mask[6], const unsigned char net[6]){
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

/**
 * return index or -1 if no free.
 */
static int next_free_consumer(){
  for ( int i = 0; i < CONSUMERS; i++ ){
    if ( MAsd[i].status == 0 ){
      return i;
    }
  }
  return -1;
}
/*
  This function adds a filter to the end of the list.
*/
int addFilter(struct FPI *newRule){
  long ret = 0;
  newRule->next=0; // Make sure that the rule does not point to some strange place.

  int index = next_free_consumer();
  if( index == -1 ){ // Problems, NO free consumers. Bail out! 
    fprintf(stderr, "No free consumers! (max: %d)\n", CONSUMERS);
    return 0;
  }
  
  newRule->filter.consumer = index;

  struct consumer* con = &MAsd[index];
  con->dropCount = globalDropcount + memDropcount;
  con->want_sendhead = newRule->filter.TYPE != 0; /* capfiles shouldn't contain sendheader */

  /* mark consumer as used */
  con->status = 1;

  const unsigned char* address = newRule->filter.DESTADDR;
  if ( newRule->filter.TYPE == 1 ){
    /* address is not passed as "01:00:00:00:00:00", but as actual memory with
     * bytes 01 00 00 ... createstream expects a string. */
    address = hexdump_address(address);
  }

  if ( (ret=createstream(&con->stream, address, newRule->filter.TYPE, MAnic, MAMPid, "caputils 0.7 test MP")) != 0 ){
    fprintf(stderr, "createstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
    exit(1);
  }

  struct ethhdr *ethhead; // pointer to ethernet header
  ethhead = (struct ethhdr*)sendmem[index];

  switch(newRule->filter.TYPE==1){
  case 3:
  case 2:
    break;
  case 1:
    memcpy(ethhead->h_dest, newRule->filter.DESTADDR, ETH_ALEN);
    break;
  case 0:
    break;
  }

  if( !myRules ){ // First rule
    myRules=newRule;
    noRules++;

    return 1;
  }

  struct FPI* cur = myRules;
  while ( cur->filter.filter_id < newRule->filter.filter_id && cur->next ){
    cur = cur->next;
  };

  if ( cur->filter.filter_id == newRule->filter.filter_id ){
    fprintf(stderr, "warning: filter rules have duplicate filter_id (%d)\n", cur->filter.filter_id);
  }

  if ( cur->filter.filter_id < newRule->filter.filter_id ) {
    /* add first */
    newRule->next = cur;
    myRules = newRule;
  } else {
    newRule->next = cur->next;
    cur->next = newRule;
  }

  noRules++;
  return 1;
}

/*
 This function finds a filter that matched the filter_id, and removes it.
*/
int delFilter(const int filter_id){
  struct FPI* cur = myRules;
  struct FPI* prev = NULL;
  while ( cur ){
    if ( cur->filter.filter_id == filter_id ){ /* filter matches */
      logmsg(verbose, "Removing filter {%d}\n", filter_id);

      /* stop consumer */
      const int consumer = cur->filter.consumer;
      struct consumer* con = &MAsd[consumer];
      stop_consumer(con);

      /* unlink filter from list */
      if ( prev ){
	prev->next = cur->next;
      } else { /* first node */
	myRules = cur->next;
      }

      free(cur);
      noRules--;
      return 0;
    }

    prev = cur;
    cur = cur->next;
  }

  logmsg(stderr, "Trying to delete non-existing filter {%d}\n", filter_id);
  return -1;
}

/**
 * Stop consumer.
 */
static void stop_consumer(struct consumer* con){
  /* no consumer */
  if ( !con || con->status == 0 ){
    return;
  }

  /* no need to flush, it will be handled by the sender eventually */

  long ret = 0;
  if ( (ret=closestream(con->stream)) != 0 ){
    fprintf(stderr, "closestream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
  }
  con->stream = NULL;
  con->status=0;
  
  return;
}

/*
 This function finds a filter and changes it.
A change will NOT allow a change of consumer, new mutlicast address is OK ,but not recommended..
*/
int changeFilter(struct FPI *newRule){
  int seeked=newRule->filter.filter_id;
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
  if(pointer1->filter.filter_id==seeked){ // Found the desired filter..It was first.fil
    newRule->filter.consumer=pointer1->filter.consumer;
    newRule->next=pointer1->next; // Make sure that the new rule points to the next.
    myRules=newRule; // Update the basepointer-> the new rule.
    free(pointer1);  // Release the old pointer. 

    ethhead= (struct ethhdr*)sendmem[newRule->filter.consumer];
    printf("\tDestination address => ");
    for(i=0;i<ETH_ALEN;i++){
      ethhead->h_dest[i]=newRule->filter.DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
      printf("%02X:",ethhead->h_dest[i]);
    }
    printf("\n");
    return(1);
  }

  while(pointer1->filter.filter_id!=seeked && pointer1->next != 0) {
    pointer2=pointer1;
    pointer1=pointer1->next;
  }
  // Two reasons to leave while loop. 1) pointer1->filter_id == seeked, 2) pointer1->next == 0
  if(pointer1->filter.filter_id==seeked){ // We found it.
    newRule->filter.consumer=pointer1->filter.consumer;
    newRule->next=pointer1->next;//Make sure that the new rule points to the next.
    pointer2->next=newRule;      // Update the previous rule so it points to the new.
    free(pointer1);              // relase the memory allocated by the old rule.

    ethhead= (struct ethhdr*)sendmem[newRule->filter.consumer];
    printf("\tDestination address => ");
    for(i=0;i<ETH_ALEN;i++){
      ethhead->h_dest[i]=newRule->filter.DESTADDR[i];   // Set the destination address, defaults to 0x01:00:00:00:[i]
      printf("%02X:",ethhead->h_dest[i]);
    }
    printf("\n");

    return(1);
  }
  // We didnt find it... (if we did at the last location, the previous if would catch it.
    return(0);

} 


void printFilters(void){
  if( !myRules ){
    printf("NO RULES\n");
    return;
  }
  
  const struct FPI *pointer=myRules;
  while( pointer != 0 ){
    marc_filter_print(stdout, &pointer->filter, 0);
    pointer = pointer->next;
  }
}
