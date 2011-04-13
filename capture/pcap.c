#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <pcap.h>

struct pcap_context {
  struct capture_context base;
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];
};

static int read_packet_pcap(struct pcap_context* ctx, unsigned char* dst, struct timeval* timestamp){
  struct pcap_pkthdr pcaphead;	/* pcap.h */
  const u_char* payload = pcap_next(ctx->handle, &pcaphead);
  if(payload==NULL) {
    logmsg(stderr, "CAPTURE_PCAP: Couldnt get payload, %s\n", pcap_geterr(ctx->handle));
    return -1;
  }

  const size_t data_len = MIN(pcaphead.caplen, PKT_CAPSIZE);
  const size_t padding = PKT_CAPSIZE - data_len;

  memcpy(dst, payload, data_len);
  memset(dst + data_len, 0, padding);
  timestamp->tv_sec = pcaphead.ts.tv_sec;
  timestamp->tv_usec = pcaphead.ts.tv_usec;

  return pcaphead.caplen;
}

/* This is the PCAP_SOCKET capturer..   */ 
void* pcap_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct pcap_context cap;

  /* initialize pcap capture */
  logmsg(verbose, "CI[%d] initializing capture on %s using pcap (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);
  cap.handle = pcap_open_live (CI->nic, BUFSIZ, 1, 0, cap.errbuf);   /* open device for reading */
  if ( !cap.handle ) {
    logmsg(stderr, "pcap_open_live(): %s\n", cap.errbuf);
    exit (1);
  }

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet_pcap;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->nic);
  pcap_close(cap.handle);

  return NULL;
}
