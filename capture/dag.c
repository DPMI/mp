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

#define RX_STREAM 0
#define TX_STREAM 1

struct dag_context {
  struct capture_context base;
  int fd;
  void* buffer;

#ifdef HAVE_DRIVER_DAG_LEGACY
  int top;
  int bottom;
#else /* HAVE_DRIVER_DAG_LEGACY */
  uint8_t* top;
  uint8_t* bottom;
#endif /* HAVE_DRIVER_DAG_LEGACY */
};

extern int dag_mode;

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
  if (payload == NULL && pload_len != 0) {
    //++pload_null_errs;
    return 0;
  }

  if (dr->flags.trunc) {
    logmsg(stderr, CAPTURE, "Truncated record\n");
    // ++ trunc_errs;
    if ( 1 /*skipflag*/ )
      return 0;
  }

  if (dr->flags.rxerror) {
    logmsg(stderr, CAPTURE, "RX error\n");
    //  ++ rx_errs;
    if ( 1 /* skipflag */ )
      return 0;
  }

  if (dr->flags.dserror) {
    logmsg(stderr, CAPTURE, "Internal error\n");
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

static int setup_device(struct CI* CI, const char* config){
  char dev[256];
  snprintf(dev, 256, "/dev/%s", CI->iface);
  
  logmsg(verbose, CAPTURE, "\tdevice: %s\n", dev);
  logmsg(verbose, CAPTURE, "\tconfig: \"%s\"\n", config);
  logmsg(verbose, CAPTURE, "\t  mode: %s\n", dag_mode == 0 ? "RXTX" : "wiretap");

  CI->sd = dag_open(dev);
  if ( CI->sd < 0 ) {
    int e = errno;
    logmsg(stderr, CAPTURE, "dag_open() on interface %s returned %d: %s\n", dev, e, strerror(e));
    return 0;
  }

  if ( dag_configure(CI->sd, (char*)config) < 0 ) {
    int e = errno;
    logmsg(stderr, CAPTURE, "dag_configure() on interface %s returned %d: %s\n", dev, e, strerror(e));
    return 0;
  }

  return 1;
}

#ifdef HAVE_DRIVER_DAG
static int read_packet(struct dag_context* cap, unsigned char* dst, struct cap_header* head){
  const ptrdiff_t diff = cap->top - cap->bottom;

  /* no packet in buffer */
  if ( diff < dag_record_size ){
    cap->top = dag_advance_stream(cap->fd, RX_STREAM, &cap->bottom);
    return 0; /* process eventual packages in the next batch */
  }

  dag_record_t* dr = (dag_record_t *) (cap->bottom);
  const size_t rlen = ntohs(dr->rlen);

  /* not enough data in buffer */
  if ( diff < rlen ){
    cap->top = dag_advance_stream(cap->fd, RX_STREAM, &cap->bottom);
    return 0; /* process eventual packages in the next batch */
  }

  /* process packet */
  int ret = process_packet(dr, dst, head);
  cap->bottom += rlen; /* advance read position */
  
  return ret;
}

static int dagcapture_init_rxtx(struct dag_context* cap){
  static const int extra_window_size = 4*1024*1024; /* manual recommends 4MB */

  int result;
  int save;
  if ( (result=dag_attach_stream(cap->fd, RX_STREAM, 0, extra_window_size)) != 0 ){
    save = errno;
    logmsg(stderr,  CAPTURE, "dag_attach_stream() failed with code 0x%02x: %s\n", save, strerror(save));
    logmsg(verbose, CAPTURE, "         FD: %d\n", cap->fd);
    logmsg(verbose, CAPTURE, "     stream: %d\n", RX_STREAM);
    logmsg(verbose, CAPTURE, "      flags: %d\n", 0);
    logmsg(verbose, CAPTURE, "   wnd size: %d bytes\n", extra_window_size);
    return save;
  }

  if ( (result=dag_start_stream(cap->fd, RX_STREAM)) != 0 ){
    save = errno;
    logmsg(stderr,  CAPTURE, "dag_start_stream() failed with code 0x%02x: %s\n", save, strerror(save));
    logmsg(verbose, CAPTURE, "      FD: %d\n", cap->fd);
    logmsg(verbose, CAPTURE, "  stream: %d\n", RX_STREAM);
    return save;
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

    dag_set_stream_poll(cap->fd, RX_STREAM, mindata, &maxwait, &poll);
  }

  return 0;
}

int dagcapture_destroy_rxtx(struct dag_context* cap){
  dag_stop_stream(cap->fd, RX_STREAM);
  dag_detach_stream(cap->fd, RX_STREAM);
  dag_close(cap->fd);
  return 0;
}

void* dag_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct dag_context cap;
  memset(&cap, 0, sizeof(struct dag_context));

  logmsg(verbose, CAPTURE, "CI[%d] initializing capture on %s using DAGv2 (memory at %p).\n", CI->id, CI->iface, &datamem[CI->id]);

  if ( !setup_device(CI, "") ){
    /* error already show */
    return NULL;
  }

  cap.fd = CI->sd;
  cap.buffer = NULL; /* not used by this driver */
  cap.top = NULL;
  cap.bottom = NULL;

  /* setup callbacks */
  cap.base.init = (init_callback)dagcapture_init_rxtx;
  cap.base.destroy = (destroy_callback)dagcapture_destroy_rxtx;
  cap.base.read_packet = (read_packet_callback)read_packet;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);
  return NULL;
}
#endif /* HAVE_DRIVER_DAG */

#ifdef HAVE_DRIVER_DAG_LEGACY
static int legacy_read_packet(struct dag_context* cap, unsigned char* dst, struct cap_header* head){
  const ssize_t diff = cap->top - cap->bottom;

  /* no packet in buffer */
  if ( diff < dag_record_size ){
    cap->top = dag_offset(cap->fd, &cap->bottom, 0);
    return 0; /* process eventual packages in the next batch */
  }

  dag_record_t* dr = (dag_record_t *)(cap->buffer + cap->bottom);
  const size_t rlen = ntohs(dr->rlen);

  /* not enough data in buffer */
  if ( diff < rlen ){
    cap->top = dag_offset(cap->fd, &cap->bottom, 0);
    return 0; /* process eventual packages in the next batch */
  }

  /* process packet */
  int ret = process_packet(dr, dst, head);
  cap->bottom += rlen; /* advance read position */
  
  return ret;
}

int dagcapture_init(struct dag_context* cap){
  int saved;
  if ( cap->buffer == MAP_FAILED ){
    saved = errno;
    logmsg(stderr, CAPTURE, "dag_mmap() returned %d: %s\n", saved, strerror(saved));
    return saved;
  }

  if ( dag_start(cap->fd) != 0 ){
    saved = errno;
    logmsg(stderr, CAPTURE, "dag_start() returned %d: %s\n", saved, strerror(saved));
    return saved;
  }

  return 0;
}

int dagcapture_destroy(struct dag_context* cap){
  dag_close(cap->fd);
  return 0;
} 

void* dag_legacy_capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct dag_context cap;

  logmsg(verbose, CAPTURE, "CI[%d] initializing capture on %s using DAGv1 (memory at %p).\n", CI->id, CI->iface, &datamem[CI->id]);

  if ( !setup_device(CI, "") ){
    /* error already show */
    return NULL;
  }

  cap.fd = CI->sd;
  cap.buffer = dag_mmap(CI->sd);
  cap.stream = 0; /* not used by this driver */
  cap.top = 0;
  cap.bottom = 0;

  /* setup callbacks */
  cap.base.init = (init_callback)dagcapture_init;
  cap.base.destroy = (destroy_callback)dagcapture_destroy;
  cap.base.read_packet = (read_packet_callback)legacy_read_packet;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);
  return NULL;
}
#endif /* HAVE_DRIVER_DAG_LEGACY */
