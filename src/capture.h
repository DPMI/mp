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

#ifndef MP_CAPTURE_H
#define MP_CAPTURE_H

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

/**
 * Guess driver from interface name.
 *  - dagN     -> DRIVER_DAG
 *  - pcap[:]* -> DRIVER_PCAP
 *  - raw[:]*  -> DRIVER_RAW
 *  - *        -> DRIVER_PCAP (if present) OR DRIVER_RAW
 * @param iface [in]
 * @param offset [out] If non-null it returns the offset to the actual
 *                     interface name (without prefix)
 */
enum CIDriver ci_driver_from_iface(const char* iface, size_t* offset);

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
	int offset;
	unsigned char* buffer;
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

/**
 * Start all capture interfaces.
 *
 * @param Sender semaphore.
 */
int setup_capture(sem_t* semaphore);

/**
 * Add a new capture interface.
 */
int add_capture(const char* iface);
void set_td(const char* arg);

/**
 * Get packet at position.
 */
struct write_header* CI_packet(struct CI* CI, int pos);

/**
 * Get selected snaplen.
 */
unsigned int snaplen();

/**
 * Calculate current buffer utilization.
 */
int buffer_utilization(struct CI* CI);

extern int volatile terminateThreads;      // used for signaling thread to terminate
extern int noCI;                           // Number of Capture Interfaces
extern int ENCRYPT;                        // If set to >0 then it will encrypt IP addresses...?
extern struct CI* _CI; /* DO _*NOT*_ USE! For backwards compability ONLY! */

// Threads
typedef void* (*capture_func)(void*);
void* capture(void*); //capture thread
void* pcap_capture(void*); //PCAP capture thread
void* dag_capture(void*);
void* dag_legacy_capture(void*);
void* control(struct thread_data* td, void*); // Control thread

/**
 * Get capture function based on driver.
 */
capture_func ci_get_function(enum CIDriver driver);

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

#endif /* MP_CAPTURE_H */
