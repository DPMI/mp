#ifndef MP_DESTINATION_H
#define MP_DESTINATION_H

#include <caputils/stream.h>
#include <caputils/filter.h>
#include <time.h>

enum state {
	IDLE,           /* unused destination */
	BUSY,           /* running */
	STOP,           /* marked for termination after next flush */
};

/**
 * MP send destination.
 *
 * Buffer
 * ------
 *
 *        begin            end
 * memory   |               |
 *      |   +----packets----+
 *      v   v               v
 *      +---+---------------+---\/\/\/\/----+
 *      |   |     DATA      |     UNUSED    |
 *      +---+---------------+---\/\/\/\/----+
 *        ^
 *        |
 *    headers (eth & send)
 *
 */
struct destination {
	struct stream* stream;             // libcap_utils stream
	struct filter* filter;             // 1:1 mapping to filter
	int index;                         // destination index 0..N

	enum state state;                  // state of this consumer
	int want_ethhead;                  // 1 if consumer want the ethernet header or 0 if just the payload (implies want_sendhead)
	int want_sendhead;                 // 1 if consumer want the sendheader or 0 if just the payload
	int sendcount;                     // number of packets in buffer
	struct sendhead* shead;            // pointer to sendheader.
	struct ethhdr* ethhead;            // pointer to ethernet header
	struct timespec last_sent;         // timestamp of the last flush

	struct {
		void* memory;                    // beginning of buffer
		void* begin;                     // pointer to first packet
		void* end;                       // pointer to next (unwritten) packet
	} buffer;
};

void destination_stop(struct destination* dst);
void destination_init(struct destination* dst, int index, size_t requested_buffer_size);
void destination_free(struct destination* dst);
void destination_init_all(size_t requested_buffer_size);
void destination_free_all();

extern struct destination MAsd[MAX_FILTERS];

#endif /* MP_DESTINATION_H */
