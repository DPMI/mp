#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <caputils/caputils.h>
#include <caputils/send.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

static const char* program_name;
static const char* iface = NULL;
static size_t mtu = 0;
static size_t size = 0;
struct ether_addr hwaddr;
static useconds_t interval = 500000;
static int running = 1;

struct packet {
	struct ethhdr eth;
	struct sendhead send;
	struct cap_header cap;
	struct ethhdr eth_inner;
	struct meta {
		uint8_t version;
		uint8_t reserved[3];
		uint32_t mtu;                  /* iface mtu */
		uint32_t size;                 /* size requested by user */
		uint32_t len;                  /* payload length */
		uint32_t checksum;             /* payload checksum */
	} meta;
	char payload[];
} __attribute__((packed));

static const char* shortopts = "i:s:t:h";
static struct option longopts[] = {
	{"iface",      required_argument, 0, 'i'},
	{"size",       required_argument, 0, 's'},
	{"interval",   required_argument, 0, 't'},
	{"help",       no_argument,       0, 'h'},
	{0,0,0,0},
};

static void show_usage(){
	printf("mp-smoke-%s - Diagnostics utility for MP\n", VERSION);
	printf("usage: %s -i IFACE [-s SIZE] [-t INTERVAL] [ADDRESS]\n"
	       "\n"
	       "  -i, --iface=IFACE    Interface to send test packets on.\n"
	       "  -s, --size=BYTES     Packet size (for payload) [default=max].\n"
	       "  -t, --interval=SEC   Delay between packets [default=0.5].\n"
	       "  -h, --help           This text.\n",
	       program_name);
}

static uint32_t adler32(unsigned char *data, size_t len){
	static const int MOD_ADLER = 65521;
	uint32_t a = 1, b = 0;

	for ( unsigned int i = 0; i < len; ++i){
		a = (a + data[i]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}

	return (b << 16) | a;
}

static void set_iface(const char* arg) {
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_MP));
	if ( s == -1 ){
		fprintf(stderr, "%s: Failed to open SOCK_RAW socket for %s: %s\n", program_name, arg, strerror(errno));
		exit(1);
	}

	struct ifreq ifr;
	strncpy(ifr.ifr_name, arg, IFNAMSIZ);

	/* check if iface exists */
	if(ioctl(s, SIOCGIFINDEX, &ifr) == -1 ) {
		fprintf(stderr, "%s: Failed to open interface %s: %s\n", program_name, arg, strerror(errno));
		exit(1);
	}

	/* get local hwaddr */
	if(ioctl(s, SIOCGIFHWADDR,&ifr) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}
	memcpy(hwaddr.ether_addr_octet, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* get MTU */
	if(ioctl(s, SIOCGIFMTU,&ifr) == -1) {
		fprintf(stderr, "%s: Failed to get MTU for interface %s: %s\n", program_name, arg, strerror(errno));
		exit(1);
	}

	mtu = ifr.ifr_mtu;
	iface = arg;

	close(s);
}

static void handle_signal(int signum){
	if ( !running ){
		fprintf(stderr, "\n%s: forcing termination\n", program_name);
		abort();
	}

	running = 0;
	fprintf(stderr, "\n%s: stopping\n", program_name);
}

int main(int argc, char* argv[]){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	int op, option_index = -1;
	while ( (op = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1 ){
		switch (op){
		case 0:   /* long opt */
		case '?': /* unknown opt */
			break;

		case 'i': /* --iface */
			set_iface(optarg);
			break;

		case 's': /* --size */
			size = atoi(optarg);
			break;

		case 't': /* --interval */
			interval = (int)(atof(optarg) * 1000 * 1000);
			break;

		case 'h': /* --help */
			show_usage();
			exit(0);

		default:
			fprintf(stderr, "%s: argument '-%c' declared but not handled.\n", program_name, op);
			abort();
		}
	}

	/* must specify interface */
	if ( !iface ){
		fprintf(stderr, "%s: Missing --iface, must specify an interface to generate packets on.\n", program_name);
		exit(1);
	}

	/* install signal handler */
	signal(SIGINT, handle_signal);

	int ret;
	stream_addr_t addr = STREAM_ADDR_INITIALIZER;
	stream_t st = NULL;

	/* parse address */
	if ( (ret=stream_addr_aton(&addr, optind < argc ? argv[optind] : "ff::00", STREAM_ADDR_ETHERNET, 0)) != 0 ){
		fprintf(stderr, "%s: failed to parse destination address: %s\n", program_name, caputils_error_string(ret));
		exit(1);
	}

	/* create output stream */
	if ( (ret=stream_create(&st, &addr, iface, "mpsmoke", "mpsmoke test stream")) != 0 ){
		fprintf(stderr, "%s: failed to create output stream: %s\n", program_name, caputils_error_string(ret));
		exit(1);
	}

	/* setup size
	 *
	 *      size
	 *       |
	 *       +--------------MTU-------+
	 *       |    +------max_send_p.--+
	 *       |    |   +-- max_cap_p.--+
	 *       v    v   v               v
	 *   +---+----+---+-----\/\/\/----+
	 *   |   |    |   |               |
	 *   +---+----+---+-----\/\/\/----+
	 *   ^   ^    ^   ^
	 *   |   |    |   +-- Payload
	 *   |   |    +------ Capture header
	 *   |   +----------- Send header
	 *   +--------------- Ethernet header
	 */

	const size_t min_size = sizeof(struct sendhead) + sizeof(struct cap_header);
	if ( size == 0 ){
		size = mtu;
	} else if ( size > mtu ){
		fprintf(stderr, "warning: size (%zd) is greater than max (%zd)\n", size, mtu);
	} else if ( size < min_size ){
		fprintf(stderr, "warning: size (%zd) is less than min (%zd)\n", size, min_size);
		exit(1);
	}
	const size_t max_send_payload = size - sizeof(struct sendhead);
	const size_t max_cap_payload = max_send_payload - sizeof(struct cap_header);
	const size_t max_payload = max_cap_payload - sizeof(struct ethhdr) - sizeof(struct meta);
	const size_t frame_size = size + sizeof(struct ethhdr);

	/* setup packet */
	struct packet* packet = (struct packet*)malloc(frame_size);
	memcpy(&packet->eth.h_source, &hwaddr, ETH_ALEN);
	memcpy(&packet->eth.h_dest, &addr.ether_addr, ETH_ALEN);
	memcpy(&packet->eth_inner.h_source, &hwaddr, ETH_ALEN);
	memcpy(&packet->eth_inner.h_dest, &addr.ether_addr, ETH_ALEN);
	packet->eth.h_proto = htons(ETHERTYPE_MP);
	packet->eth_inner.h_proto = htons(ETHERTYPE_MP_DIAGNOSTIC);
	packet->send.sequencenr = htonl(0x0000);
	packet->send.nopkts = htonl(1);
	packet->send.flags = htonl(0);
	packet->send.version.major = htons(CAPUTILS_VERSION_MAJOR);
	packet->send.version.minor = htons(CAPUTILS_VERSION_MINOR);
	strncpy(packet->cap.nic, iface, CAPHEAD_NICLEN);
	strncpy(packet->cap.mampid, "mpsmoke", 8);
	packet->cap.len = mtu;
	packet->cap.caplen = max_cap_payload;
	packet->meta.version = 1;
	packet->meta.mtu = htonl(mtu);
	packet->meta.size = htonl(size);
	packet->meta.len = htonl(max_payload);

	/* information */
	fprintf(stderr, "Sending packets on %s\n", stream_addr_ntoa(&addr));
	fprintf(stderr, "  Frame size:       %zd\n", frame_size);
	fprintf(stderr, "  MTU:              %zd\n", mtu);
	fprintf(stderr, "  Packet size:      %zd\n", size);
	fprintf(stderr, "  Sendhead payload: %zd\n", max_send_payload);
	fprintf(stderr, "  Caphead payload:  %zd\n", max_cap_payload);
	fprintf(stderr, "  Data payload:     %zd\n", max_payload);

	/* open a source for randomness */
	FILE* rnd = fopen("/dev/urandom", "r");

	int seqnr = 0;
	while ( running ){

		/* fill with random bytes and calculate checksum */
		if ( fread(packet->payload, max_payload, 1, rnd) != 1 ){
			fprintf(stderr, "%s: failed to read random data: %s\n", program_name, strerror(errno));
		}
		packet->meta.checksum = htonl(adler32(packet->payload, max_payload));
		packet->cap.ts = timepico_now();

		/* send frame */
		if ( (ret=stream_write(st, packet, frame_size)) != 0 ){
			fprintf(stderr, "%s: stream_write(..) failed: %s\n", program_name, caputils_error_string(ret));
		}
		packet->send.sequencenr = htonl((seqnr+1) % 0xFFFF);
		seqnr++;
		putc('.', stdout);
		fflush(stdout);

		usleep(interval);
	}

	putc('\n', stdout);
	fclose(rnd);
	free(packet);
	stream_close(st);

	return 0;
}
