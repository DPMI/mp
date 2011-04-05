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
#define _DEBUG

#ifdef _DEBUG
#define _DEBUG_MSG(x)	(x);fflush(stdout);
#else
#define _DEBUG_MSG(x)
#endif

#include <pthread.h>
#include <sys/socket.h>
//#include <netinet/ether.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <semaphore.h>

//#include <linux/if_ether.h>
#include <net/if_arp.h>
#define PKT_CAPSIZE 1514
#include <caputils/caputils.h>

#ifdef PF_PACKET
# include <linux/if_packet.h>
# ifdef PACKET_HOST
#  define HAVE_PF_PACKET_SOCKETS
# endif /* PACKET_HOST */
#endif /* PF_PACKET */

#ifdef SO_ATTACH_FILTER
#include <linux/types.h>
#include <linux/filter.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PKT_BUFFER  10000          //size of capture buffer in packets

#define ERRBUF_SIZE 256             //write buffer for errors
#define CI_NIC 2                    // number of capture interfaces

#define MIN(A,B) ((A) < (B) ? (A):(B))

#define minSENDSIZE 1                 // Number of packets for each send to tcpserver
#define maxSENDSIZE 70
#define CONSUMERS 20                // Number of consumers, this also places a maximum on the number of filters.
#define MYPROTO 0x0810              // Link Protocol.. Identifies a MP data frame.

#define MYPORT 2000                 // Default listen port for controller thread
#define MAPORT 1500                 // Default listen port for MArelayDaemon

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

// Global variables.
int maSendsize;                     // number of packets to include in capture payload.
struct consumer MAsd[CONSUMERS];
FILE *FILEd;                        // File descriptor for FILE.
int terminateThreads;               //used for signaling thread to terminate
int recvPkts,sentPkts, writtenPkts, matchPkts; // counters for captured ans sent packets
unsigned char my_mac[6];            // The interface mac for MA communications.
int ifindex;                        // The interface id of MAnic
char* MAnic;                        // string containing interface that connects to MAc
int MAmtu;                          // MTU of the MA interface.
int noCI;                           // Number of Capture Interfaces 
char hostname[200];                 // Hostname of MP.
int bufferUsage[CI_NIC];            // How many bytes of the buffer is used?
int ENCRYPT;                        // If set to >0 then it will encrypt IP addresses...?
char *MAIPaddr;                     // If set, this is the IP that should be used when talking on the MAnet.
int useVersion;                     // What Communication version to use, 1= v0.5 MySQL, 2=v0.6 and UDP.
int bcastS;                         // Socket used to communicate with MArNetwork.
struct sockaddr_in servAddr;        // Address structure for MArCD
struct sockaddr_in clientAddr;      // Address structure for MP

pthread_t child[CI_NIC];           // array of capture threads
pthread_t senderPID;               // thread id for the sender thread
pthread_t controlPID;              // thread id for the control thread
pthread_t mainPID;                 // thread id for the main process, ie. the daddy of all threads.

char *MAMPid;                      // String identifying the MySQL identity.

struct CI_stat{
  int recvpkts;                    // Packets that were sent to the interface
  int droppkts;                    // Packets that were dropped by the interface
};

int globalDropcount;               // Total amount of PDUs that were dropped by Interface.
int memDropcount;                  // Total amount of PDUs that were dropped between CI and Sender.


struct CI_stat CIstat[CI_NIC];                    // Statistics for capture interfaces.

struct write_header //Used for marking a packet as read or written in the shared memory
{
  int free;
  int consumer;
};
typedef struct write_header  write_head;

struct captureProcess {
  int sd;                           /* Socket to listen to */
  char* nic;                        /* String with nic identifier */
  u_char* datamem;                  /* Pointer to my memory */
  sem_t* semaphore;                    /* Semaphore Id. */
  int id;                           /* Capture ID */
  long pktCnt;                      /* How many packets have been read */
  uint8_t accuracy;                  /* Accuracy of interface, read from config file. */

};
typedef struct captureProcess capProcess;


char nic[CI_NIC][10];                // array of nic names
int tsAcc[CI_NIC];                   // array of timestamp accuracy to the ass. nics.
int sd[CI_NIC];                      // array of sockets
capProcess cp[CI_NIC];               // array of information to capture threads
capProcess ourCaptures[CI_NIC];


struct senderProcess{
  int nics;                         /* How many nics/capture processes will be present*/
  char *nic;                        /* The names of these */
  sem_t* semaphore;                    /* Semaphore */
};
typedef struct senderProcess  sendProcess;

struct saverProcess{
  int nics;                         /* How many nics/capture processes will be present*/
  char *nic;                        /* The names of these */
  sem_t* semaphore;                    /* Semaphore */
};
typedef struct saverProcess  saveProcess;

struct controllerProcess{
  int MAifIndex;                    /* Index on the MA interface */
  char* MAnic;                      /* String rep. the MA interface */
};
typedef struct controllerProcess controlProcess;


// allocate capture buffer.
u_char datamem[CI_NIC][PKT_BUFFER][(PKT_CAPSIZE+sizeof(write_head)+sizeof(cap_head))];

// allocate sendbuffer
u_char sendmem[CONSUMERS][sizeof(struct ethhdr)+sizeof(struct sendhead)+maxSENDSIZE*(sizeof(cap_head)+PKT_CAPSIZE)];

/* Filter Structure */
struct FPI{
  int filter_id;                      // Integer identifying the rule. This should be uniqe for the MP.
                                      // Could be assigned locally or from the MAc...
  u_int32_t index;                    // Which fields should we check? (2bytes == 32 bits)
  char CI_ID[8];                      // Which CI                         512
  u_int16_t VLAN_TCI;                 // VLAN id                          256
  u_int16_t ETH_TYPE;                 // Ethernet type                    128
  unsigned char ETH_SRC[6];           // Ethernet Source                  64
  unsigned char ETH_DST[6];           // Ethernet Destination             32
  u_int8_t IP_PROTO;                  // IP Payload Protocol              16
  unsigned char IP_SRC[16];           // IP Source                        8
  unsigned char IP_DST[16];           // IP Destination                   4
  u_int16_t SRC_PORT;                 // Transport Source Port            2
  u_int16_t DST_PORT;                 // Transport Destination Port       1 

  u_int16_t VLAN_TCI_MASK;            // VLAN id mask                     
  u_int16_t ETH_TYPE_MASK;            // Ethernet type mask               
  unsigned char ETH_SRC_MASK[6];      // Ethernet Source Mask                  
  unsigned char ETH_DST_MASK[6];      // Ethernet Destination Mask             
  unsigned char IP_SRC_MASK[16];      // IP Source Mask                        
  unsigned char IP_DST_MASK[16];      // IP Destination Mask                   
  u_int16_t SRC_PORT_MASK;            // Transport Source Port Mask       
  u_int16_t DST_PORT_MASK;            // Transport Destination Port Mask  
  int consumer;                       // Destination Consumer
  int CAPLEN;                         // Amount of data to capture. 
  
  unsigned char DESTADDR[22];          // Destination Address.
  int DESTPORT;                        // Destination Port, used for udp and tcp sockets.
  int TYPE;                           // Consumer Stream Type; 0-file, 1-ethernet multicast, 2-udp, 3-tcp
  
  struct FPI *next;                   // Next filter rule.
};

// Structure used to communicate to the MA relayer
struct MAINFO{ 
  int version;
  char address[16];
  int port;
  char database[64];
  char user[64];
  char password[64];
  int portUDP;
};

// Structure of the message that we receive from the MAC
/*
struct MAMSG{
  int type;
  char payload[1400];
};
*/



//struct FPI myRules[CONSUMERS];
struct FPI *myRules;
int noRules;

// Threads
void* capture(void*); //capture thread
void* pcap_capture(void*); //PCAP capture thread
void* sender(void*); // send thread
void* saver(void*); // send thread
void* control(void*); // Control thread

void CIstatus(int sig); // Runs when ever a ALRM signal is received.
int filter(char* nic,void *pkt, struct cap_header*); //filtering routine
int inet_atoP(char *dest,char *org); // Convert ASCII rep. of ethernet to normal rep.
char *hexdump_address (const unsigned char address[IFHWADDRLEN]); // Print a ethernet address. 

int matchEth(char d[],char m[], char n[]);
int addFilter(struct FPI *newRule);
int delFilter(int filter_id);
int changeFilter(struct FPI *newRule);
void flushSendBuffer(int i);
void printFilters(void); // Print all filters
void printFilter(FILE* fp, const struct FPI *F); // Print One filter
int printMysqlFilter(char *array,char *id, int seeked);

void flushBuffer(int i); // Flush sender buffer i. 

#endif
