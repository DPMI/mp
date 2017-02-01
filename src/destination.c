#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "destination.h"
#include "capture.h"

#include <string.h>
#include <netinet/in.h>

struct destination MAsd[MAX_FILTERS];

static size_t max(size_t a, size_t b){
	return (a>b) ? a : b;
}

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

void destination_init(struct destination* dst, int index, size_t requested_buffer_size){
	static const size_t header_size = sizeof(struct ethhdr) + sizeof(struct sendhead);

	dst->stream = NULL;
	dst->index = index;
	dst->state = IDLE;
	dst->sendcount = 0;

	/* setup packet buffer */
	const size_t buffer_size = max(requested_buffer_size, sizeof(struct sendhead));
	dst->buffer.memory = malloc(buffer_size + sizeof(struct ethhdr));
	dst->buffer.begin  = dst->buffer.memory + header_size;
	dst->buffer.end    = dst->buffer.begin;

	/* setup pointers */
	dst->ethhead=(struct ethhdr*)dst->buffer.memory;
	dst->shead = (struct sendhead*)(dst->buffer.memory + sizeof(struct ethhdr));

	setup_ethernet(dst->ethhead);
	setup_sendheader(dst->shead);
}

void destination_free(struct destination* dst){
	free(dst->buffer.memory);
}

void destination_init_all(size_t requested_buffer_size){
	for( int i = 0; i < MAX_FILTERS; i++) {
		destination_init(&MAsd[i], i, requested_buffer_size);
	}
}

void destination_free_all(){
	for( int i = 0; i < MAX_FILTERS; i++) {
		destination_free(&MAsd[i]);
	}
}
