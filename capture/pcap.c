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

static int read_packet_pcap(struct pcap_context* ctx, unsigned char* dst, struct cap_header* head){
  struct pcap_pkthdr* pcaphead;
  const u_char* payload;

  switch ( pcap_next_ex(ctx->handle, &pcaphead, &payload) ){
  case 1: /* ok */
    break;

  case 0: /* timeout */
    logmsg(stderr, CAPTURE, "pcap_next() timeout\n");
    return 0;
    
  case -2: /* offline capture EOF */
    logmsg(verbose, CAPTURE, "pcap offline capture EOF\n");
    return -1;

  case -1: /* error */
    logmsg(stderr, CAPTURE, "pcap_next(): %s\n", pcap_geterr(ctx->handle));
    return -1;
  }

  const size_t data_len = MIN(pcaphead->caplen, PKT_CAPSIZE);
  const size_t padding = PKT_CAPSIZE - data_len;

  memcpy(dst, payload, data_len);
  memset(dst + data_len, 0, padding);

  head->ts.tv_sec   = pcaphead->ts.tv_sec;            // Store arrival time in seconds
  head->ts.tv_psec  = pcaphead->ts.tv_usec * 1000000; // Write timestamp in picosec
  head->len         = pcaphead->caplen;
  head->caplen      = data_len;
  /*head->flags       = 0;*/

  return pcaphead->caplen;
}

/* This is the PCAP_SOCKET capturer..   */ 
void* pcap_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct pcap_context cap;

  logmsg(verbose, CAPTURE, "CI[%d] initializing capture on %s using pcap (memory at %p).\n", CI->id, CI->iface, &datamem[CI->id]);
  const char* iface;

  /* initialize pcap capture */
  if ( CI->iface[0] != ':' ){ /* live capture */
    logmsg(verbose, CAPTURE, "  pcap live capture\n");    
    iface = CI->iface;
    cap.handle = pcap_open_live (iface, BUFSIZ, 1, 0, cap.errbuf);   /* open device for reading */
  } else { /* offline capture */
    logmsg(verbose, CAPTURE, "  pcap offline capture\n");
    iface = CI->iface+1; /* +1 to remove : */
    cap.handle = pcap_open_offline (iface, cap.errbuf);
  }

  if ( !cap.handle ) {
    logmsg(stderr, CAPTURE, "pcap_open: %s\n", cap.errbuf);
    exit (1);
  }

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet_pcap;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, CAPTURE, "CI[%d] stopping capture on %s.\n", CI->id, iface);
  pcap_close(cap.handle);

  return NULL;
}
