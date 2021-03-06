/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Wed Nov 27 16:16:40 CET 2002
    copyright            : (C) 2002 by Anders Ekberg
                           (C) 2002-2005 Patrik Arlos
                           (C) 2011 David Sveningsson
                           (C) 2021 Patrik Arlos

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
#include "destination.h"
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

#define STR_EXPAND(x) #x
#define STR(x) STR_EXPAND(x)
#define DEFAULT_SNAPLEN 1536

struct packet_stat{              // struct for interface statistics
	u_int pkg_recv;
	u_int	pkg_drop;
};

static struct MPinfo MPinfoI;
static struct MPstats MPstatsI;
const struct MPinfo* MPinfo = NULL;
struct MPstats* MPstats = NULL;

static void cleanup(int sig); // Runs when program terminates

static pthread_t main_thread;
static int local = 0;       /* run in local-mode, don't try to contact MArCd */
int port = 0; /* used by control.c */
char* marc_ip = NULL; /* used by control.c */
static const char* destination = NULL;
static int cur_snaplen = DEFAULT_SNAPLEN;

int flush_flag = 0;
int verbose_flag = 0;
int debug_flag = 0;
int show_packets = 0;
FILE* verbose = NULL;

// Limit 8 chars      "01234567"
const char* SYNC    = "cisync";
const char* MAIN    = "main";
const char* SENDER  = "sender";
const char* CAPTURE = "capture";
const char* CONTROL = "control";
const char* FILTER  = "filter";


static sem_t semaphore;
pthread_t controlPID;              // thread id for the control thread

/* Globals */
int volatile terminateThreads = 0;		     //used for signaling thread to terminate
int noCI = 0;
int ENCRYPT = 0;
int dag_mode = 0; /* 0: rxtx 1: wiretap */
const char* dag_config = "varlen";
char commandline[4096];                    /* a copy of commandline arguments given */

unsigned int snaplen(){
	return cur_snaplen;
}

static void ma_nic(const char* arg) {
	struct ifreq ifr;

	if ( MPinfoI.iface ) {
		logmsg(stderr, MAIN, "Warning: overriding previous MAnic %s with %s.\n", MPinfo->iface, optarg);
		free(MPinfoI.iface);
	}

	MPinfoI.iface = strdup(arg);
	strncpy(ifr.ifr_name, MPinfo->iface, IFNAMSIZ);

	int s = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_MP));
	if ( s == -1 ){
		logmsg(stderr, MAIN, "Failed to open SOCK_RAW socket for %s: %s\n", arg, strerror(errno));
		exit(1);
	}

	/* check if iface exists */
	if(ioctl(s, SIOCGIFINDEX, &ifr) == -1 ) {
		perror("SIOCGIFINDEX");
		exit(1);
	}
	MPinfoI.ifindex = ifr.ifr_ifindex;

	/* Get my MAC */
	if(ioctl(s, SIOCGIFHWADDR,&ifr) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}
	memcpy(MPinfoI.hwaddr.ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* Get my MTU */
	if(ioctl(s, SIOCGIFMTU,&ifr) == -1) {
		perror("SIOCGIFMTU");
		exit(1);
	}
	MPinfoI.MTU = ifr.ifr_mtu; // Store the MA network MTU.

	close(s);
}





void set_local_mampid(mampid_t mampid){
	mampid_set(MPinfoI.id, mampid);
}

void update_local_mtu(){
	struct ifreq ifr;
	strncpy(ifr.ifr_name, MPinfo->iface, IFNAMSIZ);

	int s = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_MP));
	if ( s == -1 ){
		return;
	}

	if(ioctl(s, SIOCGIFMTU,&ifr) == -1) {
		return;
	}

	if ( (size_t)ifr.ifr_mtu != MPinfo->MTU ){
		logmsg(stderr, MAIN, "MTU on MArC interface has changed from %zd to %d.\n", MPinfo->MTU, ifr.ifr_mtu);
		MPinfoI.MTU = ifr.ifr_mtu;
	}
}

enum Options {
	OPTION_IGNORE = 256,
	OPTION_MAMPID,
	OPTION_COMMENT,
	OPTION_VERSION,
};

static const char* shortopts =
	"hvqd:Df:i:s:M:p:o:S:"
#ifdef HAVE_DRIVER_DAG
	"wmc:"
#endif
;
static struct option longopts[]= {
	{"local",        no_argument,       &local, 1},
	{"accuracy",     required_argument, NULL, 'd'},
	{"interface",    required_argument, NULL, 'i'},
	{"manic",        required_argument, NULL, 's'},
	{"marc",         required_argument, NULL, 'M'},
	{"id",           required_argument, NULL, OPTION_MAMPID},
	{"comment",      required_argument, NULL, OPTION_COMMENT},
	{"help",         no_argument,       NULL, 'h'},
	{"version",      no_argument,       NULL, OPTION_VERSION},
	{"port",         required_argument, NULL, 'p'},
	{"output",       required_argument, NULL, 'o'},
	{"flush",        no_argument,       &flush_flag, 1},
	{"verbose",      no_argument,       &verbose_flag, 1},
	{"debug",        no_argument,       &debug_flag, 1},
	{"quiet",        no_argument,       &verbose_flag, 0},
	{"show-packets", no_argument ,      &show_packets, 1},
	{"config",       required_argument, NULL, OPTION_IGNORE},
	{"snaplen",      required_argument, NULL, 'S'},

#ifdef HAVE_DRIVER_DAG
	{"dag.wiretap",  no_argument,       NULL, 'w'},
	{"dag.rxtx",     no_argument,       NULL, 'm'},
	{"forward",      no_argument,       NULL, 'w'},
	{"dag-config",   required_argument, NULL, 'c'},
#endif

	{0, 0, 0, 0}
};

static void show_usage(const char* program_name){
	printf("(C) 2004 Patrik Arlos <patrik.arlos@bth.se>\n");
	printf("(C) 2011 David Sveningsson <david.sveningsson@bth.se>\n");
	printf("Usage: %s [OPTION]... -i INTERFACE... -s INTERFACE\n"
	       "       %s [OPTION] --local --capfile FILENAME\n", program_name, program_name);
	printf("  -h, --help                  help (this text)\n"
	       "      --version               Display version and exit.\n"
	       "  -s, --manic=INTERFACE       MA Interface.\n"
	       "  -M, --marc=IP               MArC IP (overrides bootstrap). \n"
	       "  -p, --port=PORT             Control interface listen port [default: 2000]\n"
	       "  -i, --interface=INTERFACE   Capture Interface (REQUIRED)\n"
	       "  -S, --snaplen=BYTES         Maximum packet capture size [default: " STR(DEFAULT_SNAPLEN) "]\n"
	       "  -f, --config=FILE           Read configuration from FILE [default: mp.conf]\n"
	       "      --local                 LOCAL MODE, do not talk to MArC, capture\n"
	       "                              everything and store to file.\n"
	       "      --flush                 Force streams to be flushed (to disk or network)\n"
	       "                              on every write. It incurs a small performance\n"
	       "                              penalty but can be useful for low-traffic streams.\n"
	       "  -v, --verbose               Verbose output.\n"
	       "  -D, --debug                 Hexdump of all messages (implies --verbose).\n"
	       "      --show-packets          Print short description of captured packets.\n"
	       "  -q, --quiet                 Less output (inverse of --verbose)\n"
	       "\n"
	       "Local mode:\n"
	       "  -o, --output=FILE           Destination.\n"
	       "      --id=ID                 Set MAMPid [default: hostname]\n"
	       "      --comment=STRING        Set comment [default: MP " VERSION "]\n"
	       "(in local mode the regular DPMI filter commands work)\n");

#ifdef HAVE_DRIVER_DAG
	printf("\n");
	printf("DAG specific options:\n");
	printf("  -w, --dag.wiretap           Wiretap mode (forwards traffic).\n");
	printf("  -m  --dag.rxtx              Port A as RX and port B as TX [default].\n");
	printf("      --forward               Alias for --dag.wiretap\n");
	printf("  -c, --dag-config=STRING     Dag configuration commands. See dag manual for\n"
	       "                              details, e.g. dagfour(1). slen is always prepended\n"
	       "                              to the config. [Default: \"%s\"]\n", dag_config);
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
	logmsg(verbose, MAIN, "  Mode: %s\n", local ? "Local" : "MA");
	logmsg(verbose, MAIN, "  Snaplen: %d\n", snaplen());
	if ( local ){
		logmsg(verbose, MAIN, "  MAMPid: %s\n", mampid_get(MPinfo->id));
		logmsg(verbose, MAIN, "  Comment: %s\n", MPinfo->comment);

		if ( destination ){
			stream_addr_t addr = STREAM_ADDR_INITIALIZER;
			stream_addr_aton(&addr, destination, STREAM_ADDR_GUESS, 0);
			logmsg(verbose, MAIN, "  Destination: %s\n", stream_addr_ntoa(&addr));
		} else {
			logmsg(verbose, MAIN, "  Destination: none\n");
		}
	}
	logmsg(verbose, MAIN, "  Capture Interfaces \n");
	for ( int i = 0; i < noCI; i++) {
		logmsg(verbose, MAIN, "    CI[%d]: %s   T_delta: %d digits\n", i, _CI[i].iface, _CI[i].accuracy);
	}

	if ( MPinfo->iface ){
		logmsg(verbose, MAIN, "  MA Interface\n");
		logmsg(verbose, MAIN, "    MAnic: %s   MTU: %zd   hwaddr: %s\n", MPinfo->iface, MPinfo->MTU, hexdump_address(&MPinfo->hwaddr));
		logmsg(verbose, MAIN, "\n");
	} else {
	  logmsg(verbose, MAIN, " --LOCAL MODE-- MTU = %d iface = %p \n", MPinfo->MTU, MPinfo->iface);
	}
}

static int parse_argv(int argc, char** argv){
	int option_index = 0;
	int op;

	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 )
		switch (op){
		case '?': /* error */
			return 1;

		case 0: /* longopt with flag set */
		case OPTION_IGNORE:
		case 'f': /* already handled */
			break;

		case OPTION_MAMPID:
			mampid_set(MPinfoI.id, optarg);
			if ( strlen(MPinfo->id) < strlen(optarg) ){
				fprintf(stderr, "Warning: MAMPid `%s' too long, truncating.\n", optarg);
			}
			break;

		case OPTION_COMMENT:
			free(MPinfoI.comment);
			MPinfoI.comment = strdup(optarg);
			break;

		case OPTION_VERSION:
			exit(0);
			break;

		case 'd': // interface to listen on
			set_td(optarg);
			break;

		case 'D': /* --debug */
			debug_flag = 1;
			break;

		case 'i': // interface to listen on
			add_capture(optarg);
			break;

		case 's':  // MA Network Interface name
			ma_nic(optarg);
			break;

		case 'M': // MArC IP address
		  marc_ip=strdup(optarg);
		  fprintf(stdout, "The future MArC IP is %s.\n",optarg);
		  break;

		case 'p': // server port
			port = atoi(optarg);
			break;

		case 'o': /* --output */
			destination = optarg;
			break;

		case 'S': /* --snaplen */
			cur_snaplen = atoi(optarg);
			break;

		case 'v': /* --verbose */
			verbose_flag = 1;
			break;

		case 'q': /* --quiet */
			verbose_flag = 0;
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

		case 'c': /* --config */
			dag_config = optarg;
			break;

		default:
			assert(0 && "declared but unhandled argument");
			break;
		}

	return 0;
}

static void store_commandline(int argc, char* argv[]){
	commandline[0] = 0;
	char* dst = commandline;
	int n = sizeof(commandline);
	for ( int i = 1; i < argc; i++ ){
		int ret = snprintf(dst, n, "%s ", argv[i]);
		if ( ret < 0 ) return;

		n -= ret;
		dst += ret;
	}
}

int main (int argc, char **argv){
	{
		static char line[] = "---------------------------------------------------------------------------------------------"; /* "should be long enough for anybody" */
		int n = fprintf(stdout, "Measurement Point " VERSION " (caputils-%s)\n", caputils_version(NULL));
		fprintf(stdout, "%.*s\n", n-1, line);
	}

	/* store commandline arguments for distress bugreport message */
	store_commandline(argc, argv);

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
	gethostname(MPinfoI.hostname, HOST_NAME_MAX);


	logmsg(stderr, MAIN, "Defaults to local interface and MTU, will be replaced with real vaules if defined.\n");
	MPinfoI.MTU=100000;
	MPinfoI.iface=strdup("lo");
	
	MPinfo = &MPinfoI;
	MPstats = &MPstatsI;

	/* activating signal*/
	main_thread = pthread_self();
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGHUP, cleanup);

	sigset_t all;
	sigset_t sigmask;
	sigfillset(&all);
	sigdelset(&all, SIGINT); /* always trap SIGINT */
	sigprocmask(SIG_SETMASK, &all, &sigmask);

	/* parse_config prints errors, never fatal */
	parse_config("mp.conf", &argc, &argv, longopts);

	/* parse filter */
	struct filter filter;
	filter_from_argv(&argc, argv, &filter);

	/* parse CLI arguments */
	if ( parse_argv(argc, argv) != 0 ){
		exit(1);
	}

	/* force verbose if debug is enabled */
	verbose_flag |= debug_flag;

	/* setup vfp to stdout or /dev/null depending on verbose flag */
	verbose = stdout;
	if ( !verbose_flag ){
		verbose = fopen("/dev/null", "w");
	}

	show_configuration();

	int ret;
	if ( !local ){
		ret = ma_mode(&sigmask, &semaphore);
	} else {
		ret = local_mode(&sigmask, &semaphore, &filter, destination);
	}

	destination_free_all();

	/* only show stats on clean exit */
	if ( ret != 0 ){
		return ret;
	}

	logmsg(stderr, MAIN, "All threads finished, terminating MP.\n");
	logmsg(stderr, MAIN, "Captured %ld pkts   Sent %ld pkts in %ld messages\n", MPstats->packet_count, MPstats->written_count, MPstats->sent_count);

	logmsg(verbose, MAIN, "Releasing resources\n");
	for( int i=0; i < MAX_FILTERS; i++ ){
		if ( !MAsd[i].stream ){
			continue;
		}

		int ret = 0;
		if ( (ret=stream_close(MAsd[i].stream)) != 0 ){
			logmsg(stderr, MAIN, "stream_close() returned %d: %s\n", ret, caputils_error_string(ret));
		}
		MAsd[i].stream = NULL;
	}

	if ( sem_destroy(&semaphore) != 0 ){
		logmsg(stderr, MAIN, "%s: sem_destroy() returned %d: %s\n", argv[0], errno, strerror(errno));
	}

	mprules_clear();

	free(MPinfoI.iface);
	free(MPinfoI.comment);
	free(marc_ip);
	return 0;
} // Main end

/**
 * Signal handler for SIGTERM, SIGINT, SIGALRM
 */
static void cleanup(int sig) {
	pthread_t self=pthread_self();

	/* only main thread should handle cleanup */
	/* this is needed on platforms with bad thread handling (LinuxThreads, I'm
	 * especially looking at you) where sigmasks appears to not work. */
	if ( !pthread_equal(self, main_thread) ){
		return;
	}

	fputc('\r', stderr);
	logmsg(stderr, MAIN, "Thread %ld caught %s signal.\n", self, strsignal(sig));

	if ( terminateThreads++ == 0 ){
		logmsg(stderr, MAIN, "Received termination signal, stopping capture.\n");
	} else {
		logmsg(stderr, MAIN, "Recevied termination signal again, aborting.\n");
		abort();
	}
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
