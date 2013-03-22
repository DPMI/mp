#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "destination.h"
#include "capture.h"

#include <string.h>
#include <caputils/caputils.h>

struct destination MAsd[MAX_FILTERS];

void destination_init(struct destination* dst, int index, unsigned char* buffer){
	dst->stream = NULL;
	dst->index = index;
	dst->state = IDLE;

	/* initialize ethernet header */
	dst->ethhead = (struct ethhdr*)buffer;
	dst->ethhead->h_proto = htons(ETHERTYPE_MP);
	memcpy(dst->ethhead->h_source, &MPinfo->hwaddr, ETH_ALEN);

	/* initialize send header */
	dst->shead=(struct sendhead*)(buffer+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol
	dst->shead->sequencenr=htons(0x0000);                        // Initialize the sequencenr to zero.
	dst->shead->nopkts=htons(0);                                 // Initialize the number of packet to zero
	dst->shead->flags=htonl(0);                                  // Initialize the flush indicator.
	dst->shead->version.major=htons(CAPUTILS_VERSION_MAJOR);     // Specify the file format used, major number
	dst->shead->version.minor=htons(CAPUTILS_VERSION_MINOR);     // Specify the file format used, minor number

	const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);
	dst->sendpointer = buffer + header_size; // Set sendpointer to first place in sendmem where the packets will be stored.
	dst->sendptrref  = dst->sendpointer;     // Grab a copy of the pointer, simplifies treatment when we sent the packets.
	dst->sendcount = 0;                      // Initialize the number of pkt stored in the packet, used to determine when to send the packet.
}

void destination_init_all(){
	for( int i = 0; i < MAX_FILTERS; i++) {
		destination_init(&MAsd[i], i, sendmem[i]);
	}
}
