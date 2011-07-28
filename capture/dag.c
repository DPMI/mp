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
#include <stdlib.h>
#include <stdio.h>

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
  if ( dag_mode == 0 ){
    logmsg(verbose, CAPTURE, "\tPort A: RX\n");
    logmsg(verbose, CAPTURE, "\tPort B: TX\n");
  } else {
    logmsg(verbose, CAPTURE, "\tPort A: RX -> B [wiretap]\n");
    logmsg(verbose, CAPTURE, "\tPort B: TX -> A [wiretap]\n");
  }

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
static int read_packet_rxtx(struct dag_context* cap, unsigned char* dst, struct cap_header* head){
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

/**
 * @see dag_get_stream_poll(3) for details.
 * @param mindata min amount of bytes to return
 * @param maxwait max time to wait (set to 0 to block indefinitely)
 * @param poll time to wait between tries.
 */
static void dagcapture_set_poll(struct dag_context* cap, size_t mindata, unsigned int maxwait, unsigned int poll){
  struct timeval m;
  struct timeval p;
  timerclear(&m);
  timerclear(&p);

  m.tv_usec = maxwait * 1000;
  p.tv_usec = poll * 1000;
  
  dag_set_stream_poll(cap->fd, RX_STREAM, mindata, &m, &p);
}

static int dagcapture_error(const char* func, int code, const char* fmt, ...){
  char* buf;
  va_list ap;
  va_start(ap, fmt);
  vasprintf(&buf, fmt, ap);
  va_end(ap);
  logmsg(stderr, CAPTURE, "%s() failed with code 0x%02x: %s\n", func, code, buf);
  free(buf);
  return code;
}

static int dagcapture_init_rxtx(struct dag_context* cap){
  static const int extra_window_size = 4*1024*1024; /* manual recommends 4MB */

  int result;
  if ( (result=dag_attach_stream(cap->fd, RX_STREAM, 0, extra_window_size)) != 0 ){
    return dagcapture_error("dag_attach_stream", errno, "%s", strerror(errno));
  }

  if ( (result=dag_start_stream(cap->fd, RX_STREAM)) != 0 ){
    return dagcapture_error("dag_start_stream", errno, "%s", strerror(errno));
  }

  /* setup polling */
  dagcapture_set_poll(cap,
    32*1024, /* 32kb min data */
    100,     /* 100ms timeout */
    10       /* 10ms poll interval */
  );
 
  return 0;
}

static int dagcapture_init_wiretap(struct dag_context* cap){
  static const int extra_window_size = 4*1024*1024; /* manual recommends 4MB */

  int result;

  /* Attach two streams */
  {
    if ( (result=dag_attach_stream(cap->fd, TX_STREAM, 0, extra_window_size)) != 0 ){
      return dagcapture_error("dag_attach_stream", errno, "TX_STREAM %s", strerror(errno));
    }
    if ( (result=dag_attach_stream(cap->fd, RX_STREAM, 0, extra_window_size)) != 0 ){
      return dagcapture_error("dag_attach_stream", errno, "RX_STREAM %s", strerror(errno));
    }
  }

  /* Ensure buffer size is equal */
  {
    int rx_buffer = dag_get_stream_buffer_size(cap->fd, RX_STREAM);
    int tx_buffer = dag_get_stream_buffer_size(cap->fd, TX_STREAM);
    
    if ( rx_buffer != tx_buffer ){
      return dagcapture_error("dag_get_stream_buffer_size", EINVAL,
			      "DAG card does not appear to be correctly configured for inline operation\n\n"
			      "\t(receive buffer size = %u bytes, transmit buffer size = %u bytes).\n"
			      "\tPlease run:\n"
			      "\t    dagthree -d %s default overlap     (for DAG 3 cards)\n"
			      "\t    dagfour -d %s default overlap      (for DAG 4 cards)\n"
			      );
    }
  }

  /* Start both streams */
  {
    if ( (result=dag_start_stream(cap->fd, TX_STREAM)) != 0 ){
      return dagcapture_error("dag_start_stream", errno, "TX_STREAM %s", strerror(errno));
    }
    if ( (result=dag_attach_stream(cap->fd, RX_STREAM, 0, extra_window_size)) != 0 ){
      return dagcapture_error("dag_attach_stream", errno, "RX_STREAM %s", strerror(errno));
    }
    if ( (result=dag_start_stream(cap->fd, RX_STREAM)) != 0 ){
      return dagcapture_error("dag_start_stream", errno, "RX_STREAM %s", strerror(errno));
    }
  }

  /* setup polling */
  dagcapture_set_poll(cap,
    32*1024, /* 32kb min data */
    100,     /* 100ms timeout */
    10       /* 10ms poll interval */
  );
 
  return 0;
}

static int dagcapture_destroy_rxtx(struct dag_context* cap){
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
  if ( dag_mode == 0 ){
    cap.base.init = (init_callback)dagcapture_init_rxtx;
    cap.base.destroy = (destroy_callback)dagcapture_destroy_rxtx;
    cap.base.read_packet = (read_packet_callback)read_packet_rxtx;
  } else if ( dag_mode == 1 ){
    cap.base.init = (init_callback)dagcapture_init_wiretap;
    cap.base.destroy = 0;
    cap.base.read_packet = 0;
  } else {
    logmsg(stderr, CAPTURE, "Unsupported mode: %d\n", dag_mode);
    abort();
  }

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

static int dagcapture_init(struct dag_context* cap){
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

static int dagcapture_destroy(struct dag_context* cap){
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
