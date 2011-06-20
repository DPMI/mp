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
//#include <linux/if.h>
// 
//#define STPBRIDGES 0x0026
//#define CDPVTP 0x016E
// 
//#define TCP 4
//#define UDP 3
//#define IP 2
//#define OTHER 1

static void stop_consumer(struct consumer* con);

static char hex_string[IFHWADDRLEN * 3] = "00:00:00:00:00:00";
static unsigned char* hexdump_address (const unsigned char address[IFHWADDRLEN]){
  int i;

  for (i = 0; i < IFHWADDRLEN - 1; i++) {
    sprintf (hex_string + 3*i, "%2.2X:", address[i]);
  }  
  sprintf (hex_string + 15, "%2.2X", address[i]);
  return (unsigned char*)hex_string;
}

int filter(const char* CI, const void *pkt, struct cap_header *head){
  if ( noRules==0 ) {
    return -1;
  }

  const struct ethhdr* ether = (struct ethhdr*)pkt;
  const struct ether_vlan_header* vlan = NULL;
  struct ip* ip_hdr = NULL;

  /* setup vlan header */
  if(ntohs(ether->h_proto)==0x8100){
    vlan = (struct ether_vlan_header*)(pkt);
  }

  /* setup IP header */
  if ( vlan == NULL ) {
    if(ntohs(ether->h_proto) == ETHERTYPE_IP){
      ip_hdr=(struct ip*)(pkt+sizeof(struct ethhdr));
    }
  } else {
    if(ntohs(vlan->h_proto) == ETHERTYPE_IP){
      ip_hdr=(struct ip*)(pkt+sizeof(struct ether_vlan_header));
    }
  }

  int destination = -1;

  struct FPI* rule = myRules;
  while ( rule ){
    const struct filter* filter = &rule->filter;

    if ( filter_match(filter, pkt, head) == 1 ){
      /* packet matches */
      destination = filter->consumer;
      head->caplen = filter->caplen;
      break;
    }

    /* try next rule */
    rule = rule->next;
  }

  if( ip_hdr !=0 && ENCRYPT>0){ // It is atleast a IP header.
    unsigned char *ptr=(unsigned char *)(ip_hdr);
    ptr[15]=ptr[15] << ENCRYPT | ( ptr[15] >> (8-ENCRYPT)); // Encrypt Sender
    ptr[19]=ptr[19] << ENCRYPT | ( ptr[19] >> (8-ENCRYPT)); // Encrypt Destination
  }

  return destination;  
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
  This function adds a filter to the end of the list. The comment is a lie.
*/
int setFilter(struct FPI *newRule){
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
  con->want_sendhead = newRule->filter.type != 0; /* capfiles shouldn't contain sendheader */

  /* mark consumer as used */
  con->status = 1;

  const unsigned char* address = newRule->filter.destaddr;
  if ( newRule->filter.type == 1 ){
    /* address is not passed as "01:00:00:00:00:00", but as actual memory with
     * bytes 01 00 00 ... createstream expects a string. */
    address = hexdump_address(address);
  }

  /** @todo hardcoded stream comment */
  if ( (ret=createstream(&con->stream, address, newRule->filter.type, MA.iface, mampid_get(MA.MAMPid), MA.MPcomment)) != 0 ){
    fprintf(stderr, "createstream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
    exit(1);
  }

  struct ethhdr *ethhead; // pointer to ethernet header
  ethhead = (struct ethhdr*)sendmem[index];

  switch(newRule->filter.type==1){
  case 3:
  case 2:
    break;
  case 1:
    memcpy(ethhead->h_dest, newRule->filter.destaddr, ETH_ALEN);
    break;
  case 0:
    break;
  }

  if( !myRules ){ // First rule
    myRules=newRule;
    noRules++;

    return 1;
  }

  /* Find suitable spot in the linked list */
  struct FPI* cur = myRules;
  struct FPI* prev = NULL;
  while ( cur->filter.filter_id < newRule->filter.filter_id && cur->next ){
    prev = cur;
    cur = cur->next;
  };

  /* if the new rule should be placed last, the previous while-loop won't catch
   * it because it cannot dereference cur if it is the last (null) */
  if ( cur->filter.filter_id < newRule->filter.filter_id ){
    prev = cur;
    cur = NULL;
  }

  /* If the filter ids match assume the new filter is supposed to overwrite the previous.
   * By design, two filters cannot have the same filter_id even if it is currently possible to have it in the database */
  if ( cur && cur->filter.filter_id == newRule->filter.filter_id ){
    /* close old consumer */
    struct consumer* oldcon = &MAsd[cur->filter.consumer];
    oldcon->status = 0;
    if ( (ret=closestream(con->stream)) != 0 ){
      fprintf(stderr, "closestream() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
      exit(1);
    }
    
    /* Update existing filter */
    memcpy(&cur->filter, &newRule->filter, sizeof(struct filter));
    return 1;
  }

  if ( !prev ) {
    /* add first */
    newRule->next = cur;
    myRules = newRule;
  } else {
    /* add link */
    prev->next = newRule;
    newRule->next = cur;
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
