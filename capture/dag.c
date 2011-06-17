#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "log.h"
#include <dagapi.h>
#include <sys/mman.h> /* for mmap */
#include <arpa/inet.h> /* ntohs */
#include <errno.h>
#include <string.h>
#include <stddef.h>

struct dag_context {
  struct capture_context base;
  int fd;
  void* buffer;
  int stream;

#ifdef HAVE_DRIVER_DAG_LEGACY
  int top;
  int bottom;
#else /* HAVE_DRIVER_DAG_LEGACY */
  uint8_t* top;
  uint8_t* bottom;
#endif /* HAVE_DRIVER_DAG_LEGACY */
};

static int process_packet(dag_record_t* dr, unsigned char* dst, struct cap_header* head){
  char* payload = ((char *) dr) + dag_record_size;
  const size_t rlen = ntohs(dr->rlen); /* DAG record length */
  const size_t pload_len = rlen - dag_record_size; /* payload length */
  size_t data_len = pload_len; /* data length (payload minus additional alignment/padding) */
  size_t alignment = 0;

  //++ wire_pkts;

  if ( dr->type == TYPE_ETH ) {
    /* why? --ext 2011-06-14 */
    alignment = 4;
    payload += 2;
  } else {
    alignment = 0;
  }
  data_len -= alignment;

  /* when and why? --ext 2011-06-14 */
  if ( rlen < dag_record_size ) {
    //++rlen_errs;
    return 0;
  }

  /* when and why? --ext 2011-06-14 */
  if (payload == NULL && pload_len != 0) {
    //++pload_null_errs;
    return 0;
  }

  if (dr->flags.trunc) {
    logmsg(stderr, "Truncated record\n");
    // ++ trunc_errs;
    if ( 1 /*skipflag*/ )
      return 0;
  }

  if (dr->flags.rxerror) {
    logmsg(stderr, "RX error\n");
    //  ++ rx_errs;
    if ( 1 /* skipflag */ )
      return 0;
  }

  if (dr->flags.dserror) {
    logmsg(stderr,"Internal error\n");
    //  ++ ds_errs;
    if ( 1 /*skipflag*/ )
      return 0;
  }

  data_len = MIN(data_len, PKT_CAPSIZE);
  const size_t padding = PKT_CAPSIZE - data_len;

  memcpy(dst, payload, data_len);
  memset(dst + data_len, 0, padding);

  /* copied from /software/palDesktop/measurementpoint/src/v06/mp_fullsize (I assume it works) */ {
    unsigned long long int ts = dr->ts;
    head->ts.tv_sec=ts >> 32;
    ts = ((ts & 0xffffffffULL) * 1000ULL * 1000ULL * 1000UL * 4ULL);
    ts += (ts & 0x80000000ULL) << 1;
    head->ts.tv_psec = (ts >> 32);
    head->ts.tv_psec *= 250;       // DAG counter is based on 250ps increments..
  }

  head->len    = ntohs(dr->wlen) - 4; /* why -4? --ext 2011-06-14 */
  head->caplen = data_len;

  return head->len;
}

#ifdef HAVE_DRIVER_DAG
static int read_packet(struct dag_context* cap, unsigned char* dst, struct cap_header* head){
  const ptrdiff_t diff = cap->top - cap->bottom;

  /* no packet in buffer */
  if ( diff < dag_record_size ){
    cap->top = dag_advance_stream(cap->fd, cap->stream, &cap->bottom);
    return 0; /* process eventual packages in the next batch */
  }

  dag_record_t* dr = (dag_record_t *) (cap->bottom);
  const size_t rlen = ntohs(dr->rlen);

  /* not enough data in buffer */
  if ( diff < rlen ){
    cap->top = dag_advance_stream(cap->fd, cap->stream, &cap->bottom);
    return 0; /* process eventual packages in the next batch */
  }

  /* process packet */
  int ret = process_packet(dr, dst, head);
  cap->bottom += rlen; /* advance read position */
  
  return ret;
}

void* dag_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct dag_context cap;

  logmsg(verbose, "CI[%d] initializing capture on %s using DAGv2 (memory at %p).\n", CI->id, CI->iface, &datamem[CI->id]);

  const int stream = 0;
  const int extra_window_size = 4*1024*1024; /* manual recommends 4MB */

  cap.fd = CI->sd;
  cap.buffer = NULL; /* not used by this driver */
  cap.stream = stream;
  cap.top = NULL;
  cap.bottom = NULL;

  int result;
  if ( (result=dag_attach_stream(CI->sd, stream, 0, extra_window_size)) != 0 ){
    logmsg(stderr,  "dag_attach_stream() failed with code 0x%02x: %s\n", errno, strerror(errno));
    logmsg(verbose, "         FD: %d\n", CI->sd);
    logmsg(verbose, "     stream: %d\n", stream);
    logmsg(verbose, "      flags: %d\n", 0);
    logmsg(verbose, "   wnd size: %d bytes\n", extra_window_size);
    return NULL;
  }

  if ( (result=dag_start_stream(CI->sd, stream)) != 0 ){
    logmsg(stderr,  "dag_start_stream() failed with code 0x%02x: %s\n", errno, strerror(errno));
    logmsg(verbose, "      FD: %d\n", CI->sd);
    logmsg(verbose, "  stream: %d\n", stream);
    return NULL;
  }

  /* Initialise DAG polling parameters. (from DAG manual) */
  {
    struct timeval maxwait;
    timerclear(&maxwait);
    maxwait.tv_usec = 100 * 1000; /* 100ms timeout. */

    struct timeval poll;
    timerclear(&poll);
    poll.tv_usec = 10 * 1000;     /* 10ms poll interval. */

    const int mindata = 32*1024;  /* 32kB minimum data to return. */

    dag_set_stream_poll(CI->sd, stream, mindata, &maxwait, &poll);
  }

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->iface);
  dag_stop_stream(CI->sd, stream);
  dag_detach_stream(CI->sd, stream);
  dag_close(CI->sd);

  return 0;
}
#endif /* HAVE_DRIVER_DAG */

#ifdef HAVE_DRIVER_DAG_LEGACY
static int legacy_read_packet(struct dag_context* cap, unsigned char* dst, struct cap_header* head){
  size_t rlen;      /* DAG record length */
  size_t pload_len; /* payload length */
  size_t data_len;  /* data length (payload length minus additional alignment/padding */
  size_t alignment = 0;

  if ( cap->top - cap->bottom < dag_record_size) {
    cap->top = dag_offset(cap->fd, &cap->bottom, 0);
  }

  dag_record_t* dr = (dag_record_t *) (cap->buffer + cap->bottom);
  rlen = ntohs(dr->rlen);

  while ( cap->top - cap->bottom < rlen) {
    cap->top = dag_offset(cap->fd, &cap->bottom, 0);
    dr = (dag_record_t *) (cap->buffer + cap->bottom);
    rlen = ntohs(dr->rlen);
  }

  /* process packet */
  int ret = process_packet(dr, dst, head);
  cap->bottom += rlen; /* advance read position */
  
  return ret;
}

void* dag_legacy_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct dag_context cap;

  logmsg(verbose, "CI[%d] initializing capture on %s using DAGv1 (memory at %p).\n", CI->id, CI->iface, &datamem[CI->id]);

  cap.fd = CI->sd;
  cap.buffer = dag_mmap(CI->sd);
  cap.stream = 0; /* not used by this driver */
  cap.top = 0;
  cap.bottom = 0;

  if ( cap.buffer == MAP_FAILED ){
    logmsg(stderr, "dag_mmap() returned %d: %s\n", errno, strerror(errno));
    return NULL;
  }

  if ( dag_start(CI->sd) != 0 ){
    logmsg(stderr, "dag_start() returned %d: %s\n", errno, strerror(errno));
    return NULL;
  }

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)legacy_read_packet;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->iface);
  dag_stop(CI->sd);

  return NULL;
}
#endif /* HAVE_DRIVER_DAG_LEGACY */
