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

#include <caputils/caputils.h>
#include <libmarc/libmarc.h>
#include <stdint.h>
#include <stdio.h>
#include <semaphore.h>
 
#define PKT_BUFFER  10000          //size of capture buffer in packets
#define PKT_CAPSIZE 1514
#define CI_NIC 2                    // number of capture interfaces
 
#define MIN(A,B) ((A) < (B) ? (A):(B))
 
#define minSENDSIZE 1                 // Number of packets for each send to tcpserver */
#define maxSENDSIZE 70
#define CONSUMERS 20                // Number of consumers, this also places a maximum on the number of filters.
#define MYPROTO 0x0810              // Link Protocol.. Identifies a MP data frame.
// 
//#define MYPORT 2000                 // Default listen port for controller thread
//#define MAPORT 1500                 // Default listen port for MArelayDaemon

struct consumer {
  struct stream* stream;

  int status;                        // Status of consumer: 0 idle/free, 1 occupied/busy
  int want_sendhead;                 // 1 if consumer want the sendheader or 0 if just the payload
  int sendcount;                     // number of packets recieved but not sent
  uint16_t dropCount;                // number of drops during CONSUMERn collection time.
  void* sendpointer;                 // pointer to packet in sendmem
  void* sendptrref;                  // pointer to packet in sendmem, REFERENCE!!!
  struct sendhead* shead;            // pointer to sendheaders.
  struct ethhdr* ethhead;            // pointer to ethernet header
};

void consumer_init(struct consumer* con, unsigned char* buffer);

/* // Global variables. */
int maSendsize;                     // number of packets to include in capture payload.
struct consumer MAsd[CONSUMERS];
int volatile terminateThreads;               //used for signaling thread to terminate
int recvPkts;
int matchPkts;
int sentPkts;
int writtenPkts; // counters for captured ans sent packets

extern struct MAinfo {
  char* iface;
  mampid_t MAMPid; /* MP id */
  char* MPcomment;   /* MP comment */
  int MTU;
  struct ether_addr hwaddr;
} MA;

int noCI;                           // Number of Capture Interfaces
int ENCRYPT;                        // If set to >0 then it will encrypt IP addresses...?

int globalDropcount;               // Total amount of PDUs that were dropped by Interface.
int memDropcount;                  // Total amount of PDUs that were dropped between CI and Sender.

struct write_header //Used for marking a packet as read or written in the shared memory
{
  int free;
  int consumer;
};
typedef struct write_header write_head;

/* typedef struct captureProcess capProcess; */

enum CIDriver {
  DRIVER_UNKNOWN,
  DRIVER_RAW,
  DRIVER_PCAP,
  DRIVER_DAG,
};

#define NICLEN 256
struct CI {
  int id;
  char iface[NICLEN]; /* capture interface */
  uint8_t accuracy;   /* Accuracy of interface, read from config file. */
  enum CIDriver driver;

  int sd;
  int writepos;
  u_char* datamem;
  sem_t* semaphore;

  /* Statistics */
  long packet_count;
  long matched_count;
  int buffer_usage;    /* How many bytes of the buffer is used? */
};

extern struct CI* _CI; /* DO _*NOT*_ USE! For backwards compability ONLY! */

// allocate capture buffer.
u_char datamem[CI_NIC][PKT_BUFFER][(PKT_CAPSIZE+sizeof(write_head)+sizeof(cap_head))];

// allocate sendbuffer
u_char sendmem[CONSUMERS][sizeof(struct ethhdr)+sizeof(struct sendhead)+maxSENDSIZE*(sizeof(cap_head)+PKT_CAPSIZE)];

// Threads
void* capture(void*); //capture thread
void* pcap_capture(void*); //PCAP capture thread
void* dag_capture(void*);
void* dag_legacy_capture(void*);
void* control(void*); // Control thread

/**
 * Match packet against available filter. Will fill in head->caplen.
 * @param nic CI that captured this packet.
 * @param pkt The packet itself
 * @param head Capture header.
 * @return Recipient id or -1 if no filter matches.
 */
int filter(const char* nic, const void* pkt, struct cap_header* head); //filtering routine

typedef int (*read_packet_callback)(void* context, unsigned char* dst, struct cap_header* head);

struct capture_context {
  read_packet_callback read_packet;
};

int capture_loop(struct CI* CI, struct capture_context* cap);

#endif
