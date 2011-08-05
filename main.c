/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Wed Nov 27 16:16:40 CET 2002
    copyright            : (C) 2002 by Anders Ekberg
                           (C) 2002-2005 Patrik Arlos
                           (C) 2011 David Sveningsson
    email                : anders.ekberg@bth.se
                           patrik.arlos@bth.se
                           david.sveningsson@bth.se
                         
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
 This is the main thread of the mp. It takes care of initializations
 and post processing information.


***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "filter.h"
#include "sender.h"
#include "log.h"
#include "configfile.h"
#include "ma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <getopt.h>
#include <assert.h>
#include <caputils/caputils.h>
#include <caputils/filter.h>
#include <libmarc/filter.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <signal.h>

#ifdef HAVE_DAG
#include <dagapi.h>
#endif /* HAVE_DAG */

struct packet_stat{              // struct for interface statistics
  u_int pkg_recv;
  u_int	pkg_drop;
};

static struct MPinfo MPinfoI;
static struct MPstats MPstatsI;
const struct MPinfo* MPinfo = NULL;
struct MPstats* MPstats = NULL;

static void cleanup(int sig); // Runs when program terminates
static int packet_stats(int sd, struct packet_stat *stat); // function for collecting statistics

static void info(int sd);// function for presentating statistics

static short int iflag=0;  // number of capture interfaces
static short int tdflag=0; // Number of T_delta definitions.

static int local = 0;       /* run in local-mode, don't try to contact MArCd */
static int port = 0;
static const char* capfile = NULL;
static struct CI CI[CI_NIC];
struct CI* _CI = CI;

int verbose_flag = 0;
int debug_flag = 0;
FILE* verbose = NULL; 

const char* MAIN = "main";
const char* SENDER = "sender";
const char* CAPTURE = "capture";
const char* CONTROL = "control";
const char* FILTER = "filter";

static sem_t semaphore;
pthread_t controlPID;              // thread id for the control thread

/* Globals */
int volatile terminateThreads = 0;		     //used for signaling thread to terminate
int noCI = 0;
int ENCRYPT = 0;
int globalDropcount = 0;
int memDropcount = 0;
int dag_mode = 0; /* 0: rxtx 1: wiretap */

/* really worstcase implementation of clamp =) */
static int clamp(int v, int min, int max){
  if ( v < min ){
    return min;
  }
  if ( v > max ){
    return max;
  }
  return v;
}

static void ma_nic(const char* arg) {
  struct ifreq ifr;
  local = 0;

  if ( MPinfoI.iface ) {
    logmsg(stderr, MAIN, "Warning: overriding previous MAnic %s with %s.\n", MPinfo->iface, optarg);
    free(MPinfoI.iface);
  }

  MPinfoI.iface = strdup(arg);
  strncpy(ifr.ifr_name, MPinfo->iface, IFNAMSIZ);

  int s = socket(AF_PACKET, SOCK_RAW, htons(MYPROTO));
  if ( s == -1 ){
    logmsg(stderr, MAIN, "Failed to open SOCK_RAW socket for MA nic.\n");
    exit(1);
  }

  /* check if iface exists */
  if(ioctl(s, SIOCGIFINDEX, &ifr) == -1 ) {
    perror("SIOCGIFINDEX");
    exit(1);
  }

  /* Get my MAC */
  if ( verbose_flag ){
    if(ioctl(s, SIOCGIFHWADDR,&ifr) == -1) {
      perror("SIOCGIFHWADDR");
      exit(1);
    }

    memcpy(MPinfoI.hwaddr.ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
  }
  
  /* Get my MTU */
  if(ioctl(s, SIOCGIFMTU,&ifr) == -1) {
    perror("SIOCGIFMTU");
    exit(1);
  }
  MPinfoI.MTU = ifr.ifr_mtu; // Store the MA network MTU. 

  /* This variable should be dropped -- 2011-06-17 */
  const int sendsize = (MPinfoI.MTU - sizeof(struct sendhead))/(sizeof(cap_head)+PKT_CAPSIZE);
  maSendsize = clamp(sendsize, minSENDSIZE, maxSENDSIZE);

  close(s);
}

static void set_ci(const char* iface) {
  if ( iflag == CI_NIC ){
    logmsg(stderr, MAIN, "Cannot specify more than %d capture interface(s)\n", CI_NIC);
    exit(1);
  }

  strncpy(CI[iflag].iface, iface, NICLEN);
  CI[iflag].iface[NICLEN-1] = 0; /* force null-terminator */

  iflag++;
}

static void set_td(const char* arg) {
  CI[tdflag].accuracy = atoi(arg);

  if ( verbose_flag ){
    printf("Setting T_delta(%d) = %d.\n", iflag, CI[tdflag].accuracy);
  }

  tdflag++;
}

static void show_usage(const char* program_name){
  printf("(C) 2004 patrik.arlos@bth.se\n");
  printf("(C) 2011 david.sveningsson@bth.se\n"),
  printf("Usage: %s [OPTION]... -i INTERFACE... -s INTERFACE\n", program_name);
  printf("  -h, --help                  help (this text)\n");
  printf("  -s, --manic=INTERFACE       MA Interface. (REQUIRED)\n");
  printf("  -p, --port=PORT             Control interface listen port (default 1500)\n");
  printf("  -i, --interface=INTERFACE   Capture Interface (REQUIRED)\n");
  printf("      --local                 LOCAL MODE, do not talk to MArC, capture\n"
	 "                              everything and store to file.\n");
  printf("      --capfile=FILE          Store all captured packets in this capfile (in\n"
	 "                              addition to filter dst). Multiple filters are\n"
	 "                              aggregated.\n");
  printf("  -v, --verbose               Verbose output\n");
  printf("      --quiet                 Less output (inverse of --verbose)\n");

#ifdef HAVE_DRIVER_DAG
  printf("\n");
  printf("DAG specific options:\n");
  printf("  -w, --dag.wiretap           Wiretap mode (forwards traffic).\n");
  printf("  -m  --dag.rxtx              Port A as RX and port B as TX [default].\n");
  printf("      --forward               Alias for --dag.wiretap\n");
#endif

  printf("\n");
  printf("Available drivers:\n");
#ifdef HAVE_DRIVER_RAW
  printf("  * RAW socket\n");
#endif
#ifdef HAVE_DRIVER_PCAP
  printf("  * PCAP (prefix iface with pcap to use; e.g. \"pcapeth0\")\n");
#endif
#ifdef HAVE_DRIVER_DAG
  printf("  * Endace DAG\n");
#endif
#ifdef HAVE_DRIVER_DAG_LEGACY
  printf("  * Endace DAG (legacy API)\n");
#endif
  printf("\n");
  filter_from_argv_usage();
}

static void show_configuration(){
  logmsg(verbose, MAIN, "\n");
  logmsg(verbose, MAIN, "MP Configuration:\n");
  logmsg(verbose, MAIN, "  Capture Interfaces \n");
  for ( int i = 0; i < noCI; i++) {
    logmsg(verbose, MAIN, "    CI[%d]: %s   T_delta: %d digits\n", i, CI[i].iface, CI[i].accuracy);
  }

  logmsg(verbose, MAIN, "  MA Interface\n");
  logmsg(verbose, MAIN, "    MAnic: %s   MTU: %zd   hwaddr: %s\n", MPinfo->iface, MPinfo->MTU, ether_ntoa(&MPinfo->hwaddr));
  logmsg(verbose, MAIN, "\n");
}

enum Options {
  OPTION_IGNORE = 256
};

static struct option long_options[]= {
  {"local", 0, &local, 1},
  {"accuracy", 1, NULL, 'd'},
  {"interface", 1, NULL, 'i'},
  {"manic", 1, NULL, 's'},
  {"help", 0, NULL, 'h'},
  {"port", 1, NULL, 'p'},
  {"capfile", 1, NULL, 'c'},
  {"verbose", 0, &verbose_flag, 1},
  {"debug", 0, &debug_flag, 1},
  {"quiet", 0, &verbose_flag, 0},
  {"config", 1, NULL, OPTION_IGNORE},
  {"dag.wiretap", 0, NULL, 'w'},
  {"dag.rxtx", 0, NULL, 'm'},
  {"forward", 0, NULL, 'w'},
  {0, 0, 0, 0}
};

static int parse_argv(int argc, char** argv){
 
  int option_index = 0;
  int op;

  while ( (op = getopt_long(argc, argv, "hwmvd:i:s:p:", long_options, &option_index)) != -1 )
    switch (op){
    case 0: /* longopt with flag set */
    case OPTION_IGNORE:
      break;

    case 'd': // interface to listen on
      set_td(optarg);
      break;
      
    case 'i': // interface to listen on
      set_ci(optarg);
      break;
      
    case 's':  // MA Network Interface name
      ma_nic(optarg);
      break;

    case 'p': // server port
      port = atoi(optarg);
      break;

    case 'c': /* --capfile */
      capfile = optarg;
      break;

    case 'v':
      verbose_flag = 1;
      break;

    case 'h': /*Help*/
      show_usage(argv[0]);
      exit(0);
      break;

    case 'w': /* --dag.wiretap */
      dag_mode = 1;
      break;

    case 'm': /* --dag.rxtx */
      dag_mode = 0;
      break;

    default:
      assert(0 && "declared but unhandled argument");
      break;
    }

  return 0;
}

static int init_capture(){
  for (int i=0; i < CI_NIC; i++) {
    CI[i].id = i;
    CI[i].driver = DRIVER_UNKNOWN,
    CI[i].sd = -1;
    CI[i].datamem = NULL;
    CI[i].semaphore = NULL;
    CI[i].packet_count = 0;
    CI[i].matched_count = 0;
    CI[i].buffer_usage = 0;
    CI[i].iface[0] = 0;
    CI[i].accuracy = 0;
    pthread_mutex_init(&CI[i].mutex, NULL);
  }

  return 0;
}

// Create childprocess for each Nic
int setup_capture(){
  int ret = 0;
  void* (*func)(void*) = NULL;
  sem_t flag;

  logmsg(verbose, MAIN, "Creating capture_threads.\n");

  sem_init(&flag, 0, 0);

  for (int i=0; i < iflag; i++) {
    CI[i].semaphore = &semaphore;
    CI[i].flag = &flag;
    func = NULL;

    if ( strncmp("pcap", CI[i].iface, 4) == 0 ){
      CI[i].driver = DRIVER_PCAP;
    } else if (strncmp("dag", CI[i].iface, 3)==0) {
      CI[i].driver = DRIVER_DAG;
    } else {
      CI[i].driver = DRIVER_RAW;
    }
      
    switch ( CI[i].driver ){
    case DRIVER_PCAP:
#ifdef HAVE_DRIVER_PCAP
      memmove(CI[i].iface, &CI[i].iface[4], strlen(&CI[i].iface[4])+1); /* plus terminating */

      func = pcap_capture;
#else /* HAVE_DRIVER_PCAP */
	logmsg(stderr, MAIN, "This MP lacks support for libpcap (rebuild with --with-pcap)\n");
	return EINVAL;
#endif /* HAVE_DRIVER_PCAP */

      break;

    case DRIVER_RAW:
#ifdef HAVE_DRIVER_RAW
      func = capture;
#else /* HAVE_DRIVER_RAW */
	logmsg(stderr, MAIN, "This MP lacks support for raw packet capture (use libpcap or DAG instead or rebuild with --with-raw)\n");
	return EINVAL;
#endif /* HAVE_DRIVER_RAW */

      break;

    case DRIVER_DAG:
#ifdef HAVE_DAG
#ifdef HAVE_DRIVER_DAG
      func = dag_capture;
#else /* HAVE_DRIVER_DAG */
      func = dag_legacy_capture;
#endif

#else /* HAVE_DAG */
	logmsg(stderr, MAIN, "This MP lacks support for Endace DAG (rebuild with --with-dag)\n");
	return EINVAL;
#endif
      break;

    case DRIVER_UNKNOWN:
      abort(); /* cannot happen, defaults to RAW */
      break;
    }
  }

  /* launch all capture threads */
  for (int i=0; i < iflag; i++) {
    if ( (ret=pthread_create( &CI[i].thread, NULL, func, &CI[i])) != 0 ) {
      logmsg(stderr, MAIN, "Error creating capture thread.");
      return ret;
    }
  }

  /* await completion
   * not using flag_wait because it should wait a total of N secs and not N secs
   * per thread. */
  {
    struct timespec ts;
    if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
      int saved = errno;
      logmsg(stderr, MAIN, "clock_gettime() returned %d: %s\n", saved, strerror(saved));
      return saved;
    }
    ts.tv_sec += 20; /* 20s timeout */

    for (int i=0; i < iflag; i++) {
      if ( sem_timedwait(&flag, &ts) == 0 ){
	continue;
      }

      int saved = errno;
      switch ( saved ){
      case ETIMEDOUT:
      case EINTR:
	break;
      default:
	logmsg(stderr, MAIN, "sem_timedwait() returned %d: %s\n", saved, strerror(saved));
      }
      return saved;
    }
  }

  sem_destroy(&flag);

  return 0;
}

int main (int argc, char **argv){
  fprintf(stderr, "Measurement Point " VERSION " (caputils-" CAPUTILS_VERSION ")\n");
  fprintf(stderr, "----------------------------------------\n");

  // Init semaphore
  if ( sem_init(&semaphore, 0, 0) != 0 ){
    int saved = errno;
    fprintf(stderr, "%s: sem_init() returned %d: %s\n", argv[0], saved, strerror(saved));
    exit(1);
  }

  /* Initialize MP{info,stats} */
  memset(&MPinfoI,  0, sizeof(struct MPinfo));
  memset(&MPstatsI, 0, sizeof(struct MPstats));
  MPinfoI.comment = strdup("MP " VERSION);
  MPinfo = &MPinfoI;
  MPstats = &MPstatsI;

  /* activating signal*/
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);

  sigset_t all;
  sigset_t sigmask;
  sigfillset(&all);
  sigdelset(&all, SIGINT); /* always trap SIGINT */
  sigprocmask(SIG_SETMASK, &all, &sigmask);

  init_capture();

  /* parse_config prints errors, never fatal */
  parse_config("mp.conf", &argc, &argv, long_options);

  /* parse filter */
  struct filter filter;
  filter_from_argv(&argc, argv, &filter);

  /* parse CLI arguments */
  if ( parse_argv(argc, argv) != 0 ){
    perror("parse_argv");
    exit(1);
  }
  noCI = iflag;

  /* force verbose if debug is enabled */
  verbose_flag |= debug_flag;

  /* setup vfp to stdout or /dev/null depending on verbose flag */
  verbose = stdout;
  if ( !verbose_flag ){
    verbose = fopen("/dev/null", "w");
  }

  show_configuration();
  consumer_init_all();

  int ret;
  if ( !local ){
    ret = ma_mode(&sigmask, &semaphore);
  } else {
    ret = local_mode(&sigmask, &semaphore, &filter, capfile);
  }

  /* only show stats on clean exit */
  if ( ret != 0 ){
    return ret;
  }

  logmsg(stderr, MAIN, "All threads finished, terminating MP.\n");
  logmsg(stderr, MAIN, "Captured %ld pkts   Sent %ld pkts\n", MPstats->packet_count, MPstats->sent_count);
  
//Print out statistics on screen  
  printf("Socket stats.\n");
  for ( int i = 0; i < noCI; i++ )  {
    printf("%s\n", CI[i].iface);
    if (!strncmp("dag", CI[i].iface, 3)) {

    } else {
      info(CI[i].sd);
      close(CI[i].sd);
    }
  }
  
  printf("Closing MA connection....");
  for( int i=0; i < CONSUMERS; i++ ){
    if ( !MAsd[i].stream ){
      continue;
    }

    int ret = 0;
    if ( (ret=stream_close(MAsd[i].stream)) != 0 ){
      logmsg(stderr, MAIN, "stream_close() returned %d: %s\n", ret, caputils_error_string(ret));
    }
    MAsd[i].stream = NULL;
  }

  printf("OK.\nIt's terrible to out live your own children, so I die to.\n");
  
  if ( sem_destroy(&semaphore) != 0 ){
    logmsg(stderr, MAIN, "%s: sem_destroy() returned %d: %s\n", argv[0], errno, strerror(errno));
  }

  mprules_clear();

  free(MPinfoI.iface);
  free(MPinfoI.comment);

  return 0;
} // Main end

/**
 * Signal handler for SIGTERM, SIGINT, SIGALRM
 */
static void cleanup(int sig) {
  pthread_t self=pthread_self();
  fputc('\r', stderr);
  logmsg(stderr, MAIN, "Thread %ld caught %s signal.\n", self, strsignal(sig));
  
  if ( terminateThreads++ == 0 ){
    logmsg(stderr, MAIN, "Received termination signal, stopping capture.\n");
  } else {
    logmsg(stderr, MAIN, "Recevied termination signal again, aborting.\n");
    abort();
  }

  /* tell control thread to stop */
  if ( controlPID){
    pthread_kill(controlPID, SIGUSR1);
  }
}

//Function presenting dropped packets
static void info(int sd)
{
  struct packet_stat stat;

  if (packet_stats(sd, &stat) < 0)
  {
    (void)fprintf(stderr, "packet_stats failed\n");
    return;
  }
    (void)fprintf(stderr, "\t%d packets received by filter\n", stat.pkg_recv);
    (void)fprintf(stderr, "\t%d packets dropped by kernel\n", stat.pkg_drop);
}

//create statistics for Nic (pkgdrop)
static int packet_stats(int sd, struct packet_stat *stats){
#define HAVE_TPACKET_STATS
#ifdef HAVE_TPACKET_STATS
  struct tpacket_stats kstats;
  socklen_t len = sizeof (struct tpacket_stats);

  /*
   * Try to get the packet counts from the kernel.
   */
  if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,&kstats, &len) > -1)
  {
    stats->pkg_recv = kstats.tp_packets;
    stats->pkg_drop = kstats.tp_drops;
  }
  else
  {
    /*
     * If the error was EOPNOTSUPP, fall through, so that
     * if you build the library on a system with
     * "struct tpacket_stats" and run it on a system
     * that doesn't, it works as it does if the library
     * is built on a system without "struct tpacket_stats".
     */
    if (errno != EOPNOTSUPP)
    {
      printf("stats: %d", errno);
      return -1;
    }
  }
#else
  printf("missing PACKET_STATISTICS\n");
#endif
  return 0;
}

/* // Function for connecting to tcpserver */
/* int tcp_connect(const char *serv, int port){ */
/*   printf("tcp_connect() \n"); */
/*   int sockfd,result; */
/*   struct sockaddr_in	servaddr; */
/*   sockfd = socket(AF_INET, SOCK_STREAM , 0); */
/*   iface_bind(sockfd,ifindex); // Bind to MArC interface. */

/*   bzero(&servaddr, sizeof(servaddr)); */
/*   servaddr.sin_family = AF_INET; */
/*   servaddr.sin_port=htons(port); */
/*   inet_aton(serv, &servaddr.sin_addr); */
/*   setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */

/*   result=connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr)); */
/*   if(result!=0)  { */
/*     perror("tcp_connect, fail "); */
/*     return(0); */
/*   } */

/*   printf("tcp_connect, successfull. %s:%d \n", serv, port); */

/*   struct sendhead SH; */
/*   SH.sequencenr=-1; */
/*   SH.nopkts=0; */
/*   SH.flush=0; */
/*   SH.version.major=htons(CAPUTILS_VERSION_MAJOR); */
/*   SH.version.minor=htons(CAPUTILS_VERSION_MINOR); */
/*   write(sockfd,&SH,sizeof(struct sendhead)); */
/*   printf("Sent File header.\n"); */

/*   return(sockfd); */
/* } */
/* /\* end tcp_connect *\/ */



/* // Function for connecting to tcpserver */
/* int udp_connect(const char *serv, int port){ */
/*   printf("udp_connect() \n"); */
/*   int sockfd,result,rc; */
/*   struct sockaddr_in	servaddr, cliaddr; */
/*   sockfd = socket(AF_INET, SOCK_DGRAM , 0); */
/* //  setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option) ); */
/*   bzero(&servaddr, sizeof(servaddr)); */
/*   servaddr.sin_family = AF_INET; */
/*   servaddr.sin_port=htons(port); */
/*   inet_aton(serv, &servaddr.sin_addr); */
/*   cliaddr.sin_family = AF_INET; */
/*   cliaddr.sin_addr.s_addr = htonl(INADDR_ANY); */
/*   cliaddr.sin_port = 0; */

/*   rc=bind(sockfd, (struct sockaddr *)&cliaddr,sizeof(cliaddr)); */
/*   if(rc<0){ */
/*     perror("udp_connect, fail to bind."); */
/*     return(0); */
/*   } */
/*   iface_bind(sockfd,ifindex); // Bind to MArC interface. */
/*   result=connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr)); */
/*   if(result!=0)  { */
/*     perror("udp_connect, fail"); */
/*     return(0); */
/*   } */

/*   printf("udp_connect, successfull. %s:%d \n", serv, port); */
/*   return(sockfd); */
/* } */
/* /\* end udp_connect *\/ */

/* static void socket_stats(int sd,int cid) { */
/*   struct packet_stat stat; */
/*   if (packet_stats(sd, &stat) < 0) */
/*   { */
/*     (void)fprintf(stderr, "packet_stats failed\n"); */
/*     return; */
/*   } */
/*   CIstat[cid].recvpkts=stat.pkg_recv; */
/*   CIstat[cid].droppkts=stat.pkg_drop; */
/*   return; */
/* } */
