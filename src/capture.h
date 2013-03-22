/***************************************************************************
                          capture.h  -  description
                             -------------------
    begin                : Wed Nov 27 2002
    copyright            : (C) 2002 by Anders Ekberg
                          (C)2002-2005 by Patrik Arlos
    email                : anders.ekberg@bth.se
                           patrik.arlos@bth.se

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
 This is the header file for the mpcapture and contains basic definitions and
 functioncalls.
***************************************************************************/

#ifndef CAPT
#define CAPT

#include "thread.h"
#include <caputils/caputils.h>
#include <caputils/marc.h>
#include <caputils/log.h>
#include <caputils/send.h>
#include <stdint.h>
#include <stdio.h>
#include <semaphore.h>
#include <unistd.h>

#define MIN(A,B) ((A) < (B) ? (A):(B))

/* according to gethostname(2) it is 256 on linux but doesn't always seem to be
 * defined. */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#define maxSENDSIZE 70

enum state {
	IDLE,
	BUSY,
	STOP,
};

/**
 * MP send destination.
 */
struct destination {
	struct stream* stream;
	struct filter* filter;
	int index;

	enum state state;                  /* state of this consumer */
	int want_ethhead;                  // 1 if consumer want the ethernet header or 0 if just the payload (implies want_sendhead)
	int want_sendhead;                 // 1 if consumer want the sendheader or 0 if just the payload
	int sendcount;                     // number of packets recieved but not sent
	void* sendpointer;                 // pointer to packet in sendmem
	void* sendptrref;                  // pointer to packet in sendmem, REFERENCE!!!
	struct sendhead* shead;            // pointer to sendheaders.
	struct ethhdr* ethhead;            // pointer to ethernet header
	struct timespec last_sent;         // timestamp of the last flush
};

extern const struct MPinfo {
	char* iface;                       /* Name of the MA interface */
	char* comment;                     /* MP comment */
	char hostname[HOST_NAME_MAX+1];    /* Local hostname */
	mampid_t id;                       /* MAMPid (empty string when not authorized) */
	size_t MTU;                        /* MA interface MTU */
	size_t ifindex;                    /* MA interface index */
	struct ether_addr hwaddr;          /* MA interface hwaddr */
} *MPinfo;

struct MPstats {
	long packet_count;   /* number of received packages */
	long matched_count;  /* number of packages with matched a filter */
	long dropped_count;  /* number of packages with matched a filter */
	long sent_count;     /* number of capture packages sent (contains many packages) */
	long written_count;  /* number of actual packages sent */
};
extern struct MPstats* MPstats;

enum CIDriver {
	DRIVER_UNKNOWN,
	DRIVER_RAW,
	DRIVER_PCAP,
	DRIVER_DAG,
};

struct write_header //Used for marking a packet as read or written in the shared memory
{
	int used;           /* 1 if block is used. */
	int destination;    /* destination index */
	struct cap_header cp[0];
};
typedef struct write_header write_head;

struct CI {
	int id;
	char* iface;        /* capture interface */
	uint8_t accuracy;   /* Accuracy of interface, read from config file. */
	enum CIDriver driver;

	int sd;
	int writepos;
	int readpos;
	u_char* datamem;
	sem_t* flag;
	sem_t* semaphore;
	pthread_t thread;
	pthread_mutex_t mutex;

	/* Statistics */
	struct format format;
	long packet_count;          /* Total number of received packets */
	long matched_count;         /* Total number of matched packets */
	long dropped_count;         /* Total number of dropped packets */
	int seq_drop;               /* How many packets in (current) sequence has been dropped */
};

void destination_init(struct destination* dst, int index, unsigned char* buffer);
void destination_init_all();

/**
 * Get selected snaplen.
 */
int snaplen();

/**
 * Calculate current buffer utilization.
 */
int buffer_utilization(struct CI* CI);


/* // Global variables. */
struct destination MAsd[MAX_FILTERS];

extern int volatile terminateThreads;      // used for signaling thread to terminate
extern int noCI;                           // Number of Capture Interfaces
extern int ENCRYPT;                        // If set to >0 then it will encrypt IP addresses...?
extern struct CI* _CI; /* DO _*NOT*_ USE! For backwards compability ONLY! */

// allocate capture buffer.
extern u_char datamem[CI_NIC][PKT_BUFFER][(PKT_CAPSIZE+sizeof(write_head)+sizeof(cap_head))];

// allocate sendbuffer
u_char sendmem[MAX_FILTERS][sizeof(struct ethhdr)+sizeof(struct sendhead)+maxSENDSIZE*(sizeof(cap_head)+PKT_CAPSIZE)];

// Threads
void* capture(void*); //capture thread
void* pcap_capture(void*); //PCAP capture thread
void* dag_capture(void*);
void* dag_legacy_capture(void*);
void* control(struct thread_data* td, void*); // Control thread

/**
 * Match packet against available filter. Will fill in head->caplen.
 * @param nic CI that captured this packet.
 * @param pkt The packet itself
 * @param head Capture header.
 * @return Recipient id or -1 if no filter matches.
 */
int filter(const char* nic, void* pkt, struct cap_header* head); //filtering routine

typedef int (*init_callback)(void* context);
typedef int (*destroy_callback)(void* context);
typedef int (*read_packet_callback)(void* context, unsigned char* dst, struct cap_header* head);
typedef int (*stats_callback)(void* context);

struct capture_context {
	const char* iface;                    /* Name of the interface, copied reference */

	/* callbacks */
	init_callback init;
	destroy_callback destroy;
	read_packet_callback read_packet;
	stats_callback stats;
};

/**
 * Setup capturing.
 *
 * @param iface Name of the interface to capture on. (Memory is only referenced)
 */
int capture_init(struct capture_context* cap, const char* iface);
int capture_loop(struct CI* CI, struct capture_context* cap);

#endif
