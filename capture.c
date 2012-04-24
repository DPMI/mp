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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifndef ETHERTYPE_IPV6 /* libc might not provide this if it is missing ipv6 support */
#define ETHERTYPE_IPV6 0x86dd
#endif /* ETHERTYPE_IPV6 */

#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

extern int show_packets;

static void print_tcp(FILE* dst, const struct ip* ip, const struct tcphdr* tcp){
  fprintf(dst, "TCP(HDR[%d]DATA[%0x]):\t [",4*tcp->doff, ntohs(ip->ip_len) - 4*tcp->doff - 4*ip->ip_hl);
  if(tcp->syn) {
    fprintf(dst, "S");
  }
  if(tcp->fin) {
    fprintf(dst, "F");
  }
  if(tcp->ack) {
      fprintf(dst, "A");
  }
  if(tcp->psh) {
    fprintf(dst, "P");
  }
  if(tcp->urg) {
    fprintf(dst, "U");
  }
  if(tcp->rst) {
    fprintf(dst, "R");
  }

  fprintf(dst, "] %s:%d ",inet_ntoa(ip->ip_src),(u_int16_t)ntohs(tcp->source));
  fprintf(dst, " --> %s:%d",inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(tcp->dest));
  fprintf(dst, "\n");
}

static void print_udp(FILE* dst, const struct ip* ip, const struct udphdr* udp){
  fprintf(dst, "UDP(HDR[8]DATA[%d]):\t %s:%d ",(u_int16_t)(ntohs(udp->len)-8),inet_ntoa(ip->ip_src),(u_int16_t)ntohs(udp->source));
  fprintf(dst, " --> %s:%d", inet_ntoa(ip->ip_dst),(u_int16_t)ntohs(udp->dest));
  fprintf(dst, "\n");
}

static void print_icmp(FILE* dst, const struct ip* ip, const struct icmphdr* icmp){
  fprintf(dst, "ICMP:\t %s ",inet_ntoa(ip->ip_src));
  fprintf(dst, " --> %s ",inet_ntoa(ip->ip_dst));
  fprintf(dst, "Type %d , code %d", icmp->type, icmp->code);
  if( icmp->type==0 && icmp->code==0){
    fprintf(dst, " echo reply: SEQNR = %d ", icmp->un.echo.sequence);
  }
  if( icmp->type==8 && icmp->code==0){
    fprintf(dst, " echo reqest: SEQNR = %d ", icmp->un.echo.sequence);
  }
  fprintf(dst, "\n");
}

static void print_ipv4(FILE* dst, const struct ip* ip){
  void* payload = ((char*)ip) + 4*ip->ip_hl;
  fprintf(dst, "IPv4(HDR[%d])[", 4*ip->ip_hl);
  fprintf(dst, "Len=%d:",(u_int16_t)ntohs(ip->ip_len));
  fprintf(dst, "ID=%d:",(u_int16_t)ntohs(ip->ip_id));
  fprintf(dst, "TTL=%d:",(u_int8_t)ip->ip_ttl);
  fprintf(dst, "Chk=%d:",(u_int16_t)ntohs(ip->ip_sum));

  if(ntohs(ip->ip_off) & IP_DF) {
    fprintf(dst, "DF");
  }
  if(ntohs(ip->ip_off) & IP_MF) {
    fprintf(dst, "MF");
  }

  fprintf(dst, " Tos:%0x]:\t",(u_int8_t)ip->ip_tos);

  switch( ip->ip_p ) {
  case IPPROTO_TCP:
    print_tcp(dst, ip, (const struct tcphdr*)payload);
    break;

  case IPPROTO_UDP:
    print_udp(dst, ip, (const struct udphdr*)payload);
    break;

  case IPPROTO_ICMP:
    print_icmp(dst, ip, (const struct icmphdr*)payload);
    break;

  default:
    fprintf(dst, "Unknown transport protocol: %d \n", ip->ip_p);
    break;
  }
}

static void print_eth(FILE* dst, const struct ethhdr* eth){
  void* payload = ((char*)eth) + sizeof(struct ethhdr);
  uint16_t h_proto = ntohs(eth->h_proto);
  uint16_t vlan_tci;

 begin:
  switch ( h_proto ){
  case ETHERTYPE_VLAN:
      vlan_tci = ((uint16_t*)payload)[0];
      h_proto = ntohs(((uint16_t*)payload)[0]);
      payload = ((char*)eth) + sizeof(struct ethhdr);
      fprintf(dst, "802.1Q vlan# %d: ", 0x0FFF&ntohs(vlan_tci));
      goto begin;

  case ETHERTYPE_IP:
    print_ipv4(dst, (struct ip*)payload);
    break;

  case ETHERTYPE_IPV6:
    printf("ipv6\n");
    break;

  case ETHERTYPE_ARP:
    printf("arp\n");
    break;

  case 0x0810:
    fprintf(dst, "MP packet\n");
    break;

  case STPBRIDGES:
    fprintf(dst, "STP(0x%04x): (spanning-tree for bridges)\n", h_proto);
    break;

  case CDPVTP:
    fprintf(dst, "CDP(0x%04x): (CISCO Discovery Protocol)\n", h_proto);
    break;

  default:
    fprintf(dst, "Unknown ethernet protocol (0x%04x)\n", h_proto);
    break;
  }
}

static void print_packet(FILE* dst, cap_head* caphead){
  static long pkt_counter = 0;

  fprintf(dst, "[%04ld] ", ++pkt_counter);
  print_eth(dst, caphead->ethhdr);
}

static int push_packet(struct CI* CI, write_head* whead, cap_head* head, const unsigned char* packet_buffer){
  const int recipient = filter(CI->iface, packet_buffer, head);
  if ( recipient == -1 ){ /* no match */
    return -1;
  }

  if ( show_packets ){
    print_packet(stderr, head);
  }

  // prevent the reader from operating on the same chunk of memory.
  pthread_mutex_lock(&CI->mutex);
  {
    whead->free++; //marks the post that it has been written
    whead->consumer = recipient;
    CI->buffer_usage++;

    if ( whead->free>1 ){ //Control buffer overrun
      logmsg(stderr, CAPTURE, "CI[%d] OVERWRITING: %ld @ %d for the %d time \n", CI->id, pthread_self(), CI->writepos, whead->free);
      logmsg(stderr, CAPTURE, "CI[%d] bufferUsage=%d\n", CI->id, CI->buffer_usage);
    }
  }
  pthread_mutex_unlock(&CI->mutex);

  /* increment write position */
  CI->writepos = (CI->writepos+1) % PKT_BUFFER;

  /* flag that another packet is ready */
  if ( sem_post(CI->semaphore) != 0 ){
    logmsg(stderr, CAPTURE, "sem_post() returned %d: %s\n", errno, strerror(errno));
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
  int ret;

  /* initialize driver */
  if ( cap->init && (ret=cap->init(cap)) != 0 ){
    sem_post(CI->flag); /* unlock parent */
    return ret; /* return error */
  }

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

  /* stop capture */
  logmsg(verbose, CAPTURE, "CI[%d] stopping capture on %s.\n", CI->id, CI->iface);

  /* show stats */
  if ( cap->stats ){
	  cap->stats(cap);
  }

  /* driver cleanup */
  if ( cap->destroy && (ret=cap->destroy(cap)) != 0 ){
    return ret; /* return error */
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

  /* set the ethernet source address to adress used by the MA iface. */
  memcpy(con->ethhead->h_source, &MPinfo->hwaddr, ETH_ALEN);

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
