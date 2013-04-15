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
#include "destination.h"
#include "filter.h"
#include "log.h"

#include <caputils/capture.h>
#include <caputils/filter.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <string.h>
//#include <linux/if.h>

extern int flush_flag;
static struct rule* rules = NULL;
static size_t rule_count = 0;

static void stop_destination(struct destination* con);

int filter(const char* CI, void *pkt, struct cap_header *head){
	/* fast path */
	if ( mprules_count() == 0 ) {
		return -1;
	}

	const struct ethhdr* ether = (const struct ethhdr*)pkt;
	const struct ether_vlan_header* vlan = NULL;
	struct ip* ip_hdr = NULL;

	/* setup vlan header */
	if(ntohs(ether->h_proto)==0x8100){
		vlan = (const struct ether_vlan_header*)(pkt);
	}

	/* if listening on the same iface as capturing (i.e. -i and -s is the same), ignore mp packages */
	if ( ntohs(ether->h_proto) == 0x0810 ){
		return -1;
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

	struct rule* cur = mprules();
	while ( cur ){
		if ( !filter_match(&cur->filter, pkt, head) ){
			cur = cur->next;
			continue;
		}

		/* packet matches */
		destination  = cur->filter.consumer;
		head->caplen = MIN(head->caplen, cur->filter.caplen);
		break;
	}

	if( ip_hdr !=0 && ENCRYPT>0){ // It is atleast a IP header.
		unsigned char *ptr=(unsigned char *)(ip_hdr);
		ptr[15]=ptr[15] << ENCRYPT | ( ptr[15] >> (8-ENCRYPT)); // Encrypt Sender
		ptr[19]=ptr[19] << ENCRYPT | ( ptr[19] >> (8-ENCRYPT)); // Encrypt Destination
	}

	return destination;
}

static struct destination* next_free_destination(){
	for ( int i = 0; i < MAX_FILTERS; i++ ){
		if ( MAsd[i].state == IDLE ) return &MAsd[i];
	}
	return NULL;
}

size_t mprules_count(){
	return rule_count;
}

struct rule* mprules(){
	return rules;
}

static void truncate_caplen(struct filter* filter, int want_ethhdr, int want_sendhead){
	const size_t header_size =
		sizeof(struct sendhead) * want_sendhead +
		sizeof(struct cap_header);

	if ( filter->caplen + header_size > MPinfo->MTU ){
		const size_t max_caplen = MPinfo->MTU - header_size;
		logmsg(stderr, FILTER, "caplen (%d) to large for this MP, truncating to %zd\n", filter->caplen, max_caplen);
		filter->caplen = max_caplen;
	}
}

int mprules_add(const struct filter* filter){
	long ret = 0;

	struct destination* dst = next_free_destination();
	if( !dst ){ // Problems, NO free destination. Bail out!
		logmsg(stderr, FILTER, "No free destination buffer! (max: %d)\n", MAX_FILTERS);
		return ENOBUFS;
	}

	/* allocate rule */
	struct rule* rule = malloc(sizeof(struct rule));
	rule->destination = NULL;
	rule->next = NULL;
	memcpy(&rule->filter, filter, sizeof(struct filter));

	/* if the destination is /dev/null this triggers a fast-path where the packet is discarded */
	const int discard_filter = \
		stream_addr_type(&rule->filter.dest) == STREAM_ADDR_CAPFILE &&
		strcmp(rule->filter.dest.filename, "/dev/null") == 0;

	/* toggle flush flag (can only be used at clients) */
	if ( flush_flag ){
		rule->filter.dest._flags |= htons(STREAM_ADDR_FLUSH);
	}

	if ( !discard_filter ){
		/* setup destination for this filter */
		rule->destination = dst;
		rule->filter.consumer = dst->index;
		dst->filter = &rule->filter;
		dst->want_ethhead  = stream_addr_type(&rule->filter.dest) == STREAM_ADDR_ETHERNET; /* only ethernet streams need ethernet header */
		dst->want_sendhead = stream_addr_type(&rule->filter.dest) != STREAM_ADDR_CAPFILE;  /* all but capfiles need sendheader */

		/* ensure caplen is small enough to fit at least one packet in a frame */
		truncate_caplen(&rule->filter, dst->want_ethhead, dst->want_sendhead);

		/* mark destination as used */
		dst->state = BUSY;

		/* Open libcap stream */
		if ( (ret=stream_create(&dst->stream, &rule->filter.dest, MPinfo->iface, mampid_get(MPinfo->id), MPinfo->comment)) != 0 ){
			logmsg(stderr, FILTER, "stream_create() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
			exit(1);
		}

		/* Setup headers */
		switch( stream_addr_type(&rule->filter.dest) ){
		case STREAM_ADDR_TCP:
		case STREAM_ADDR_UDP:
			break;
		case STREAM_ADDR_ETHERNET:
		{
			struct ethhdr *ethhead = dst->ethhead;
			memcpy(ethhead->h_dest, &rule->filter.dest.ether_addr, ETH_ALEN);
		}
		break;
		case STREAM_ADDR_CAPFILE:
			break;
		case STREAM_ADDR_GUESS:
		case STREAM_ADDR_FP:
		case STREAM_ADDR_FIFO:
			logmsg(stderr, FILTER, "illegal destination address\n");
			abort();
		}
	} else {
		rule->filter.consumer = -1; /* will give a no-match when filtering */
	}

	/* First rule */
	if( !rules ){
		rules = rule;
		rule_count++;
		return 1;
	}

	/* Find suitable spot in the linked list */
	struct rule* cur = rules;
	struct rule* prev = NULL;
	while ( cur->filter.filter_id < rule->filter.filter_id && cur->next ){
		prev = cur;
		cur = cur->next;
	};

	/* if the new rule should be placed last, the previous while-loop won't catch
	 * it because it cannot dereference cur if it is the last (null) */
	if ( cur->filter.filter_id < rule->filter.filter_id ){
		prev = cur;
		cur = NULL;
	}

	/* If the filter ids match assume the new filter is supposed to overwrite the previous.
	 * By design, two filters cannot have the same filter_id even if it is currently possible to have it in the database */
	if ( cur && cur->filter.filter_id == rule->filter.filter_id ){
		const int index = cur->filter.consumer;
		int seqnum = 0;

		/* close old destination (if the old destination is -1 it means no actual stream
		 * is bound, this can happen if for instance a discard destination is used) */
		if ( index >= 0 ){
			struct destination* old = &MAsd[index];
			seqnum = old->shead->sequencenr;

			/* if the destination need to be flushed the seqnum needs to be increased by
			 * one as an additional frame will be sent */
			if ( old->sendcount > 0 ){
				seqnum++;
			}

			/* defer closing stream until sender has processed it */
			destination_stop(old);
		}

		/* Update existing filter */
		memcpy(&cur->filter, &rule->filter, sizeof(struct filter));

		/* restore sequence number */
		dst->shead->sequencenr = seqnum;

		return 1;
	}

	if ( !prev ) {
		/* add first */
		rule->next = cur;
		rules = rule;
	} else {
		/* add link */
		prev->next = rule;
		rule->next = cur;
	}

	rule_count++;

	return 1;
}

/*
  This function finds a filter that matched the filter_id, and removes it.
*/
int mprules_del(const unsigned int filter_id){
	struct rule* cur = rules;
	struct rule* prev = NULL;
	while ( cur ){
		if ( cur->filter.filter_id == filter_id ){ /* filter matches */
			logmsg(verbose, FILTER, "Removing filter {%d}\n", filter_id);

			/* stop destination */
			struct destination* dst = cur->destination;
			stop_destination(dst);

			/* unlink filter from list */
			if ( prev ){
				prev->next = cur->next;
			} else { /* first node */
				rules = cur->next;
			}

			free(cur);
			rule_count--;
			return 0;
		}

		prev = cur;
		cur = cur->next;
	}

	logmsg(stderr, FILTER, "Trying to delete non-existing filter {%d}\n", filter_id);
	return -1;
}

int mprules_clear(){
	struct rule* cur = rules;
	while ( cur ){
		struct rule* tmp = cur;
		cur = cur->next;
		free(tmp); /** @todo create a filter cleanup function */
	}
	return 0;
}

/**
 * Stop destination.
 */
static void stop_destination(struct destination* dst){
	/* no destination */
	if ( !dst || dst->state == IDLE ){
		return;
	}

	/* no need to flush, it will be handled by the sender eventually */

	long ret = 0;
	if ( (ret=stream_close(dst->stream)) != 0 ){
		logmsg(stderr, FILTER, "stream_close() returned 0x%08lx: %s\n", ret, caputils_error_string(ret));
	}
	dst->stream = NULL;
	dst->state = IDLE;

	return;
}

void printFilters(void){
	if( !rules ){
		printf("NO RULES\n");
		return;
	}

	const struct rule* pointer = rules;
	while( pointer != 0 ){
		filter_print(&pointer->filter, stdout, 0);
		pointer = pointer->next;
	}
}
