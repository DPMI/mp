#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "destination.h"
#include "capture.h"

#include <string.h>
#include <netinet/in.h>

struct destination MAsd[MAX_FILTERS];

static void setup_ethernet(struct ethhdr* ethhdr){
	ethhdr->h_proto = htons(ETHERTYPE_MP);

	/* set the ethernet source address to adress used by the MA iface. */
	memcpy(ethhdr->h_source, &MPinfo->hwaddr, ETH_ALEN);
}

static void setup_sendheader(struct sendhead* shead){
	shead->sequencenr = htons(0x0000);
	shead->nopkts = htons(0);
	shead->flags = htonl(0);
	shead->version.major = htons(CAPUTILS_VERSION_MAJOR);
	shead->version.minor = htons(CAPUTILS_VERSION_MINOR);
}

void destination_stop(struct destination* dst){
	dst->state = STOP;
}

void destination_init(struct destination* dst, int index, unsigned char* buffer){
	dst->stream = NULL;
	dst->index = index;
	dst->state = IDLE;
	dst->sendcount = 0;

	/* setup packet buffer */
	const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
	dst->sendpointer = buffer + header_size;   // Set sendpointer to first place in sendmem where the packets will be stored.
	dst->sendptrref  = dst->sendpointer;       // Grab a copy of the pointer, simplifies treatment when we sent the packets.

	/* setup pointers */
	dst->ethhead=(struct ethhdr*)buffer;
	dst->shead = (struct sendhead*)(buffer+sizeof(struct ethhdr));

	setup_ethernet(dst->ethhead);
	setup_sendheader(dst->shead);
}

void destination_init_all(){
	for( int i = 0; i < MAX_FILTERS; i++) {
		destination_init(&MAsd[i], i, sendmem[i]);
	}
}
