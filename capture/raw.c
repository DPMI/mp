#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "log.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

struct raw_context {
  struct capture_context base;
  int socket;
};

static int read_packet_raw(struct raw_context* ctx, unsigned char* dst, struct timeval* timestamp){
  int sd = ctx->socket;
  struct timeval timeout = {1, 0};
  
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sd, &fds);

  /* wait until data is available on socket */  
  if ( select(sd+1, &fds, NULL, NULL, &timeout) == -1 ){
    switch ( errno ){
    case EAGAIN:
    case EINTR:
      return 0;
      
    default:
      logmsg(stderr, "select() failed with code %d: %s\n", errno, strerror(errno));
      return -1;
    }
  }

  /* read from socket */
  const ssize_t bytes = recvfrom(sd, dst, PKT_CAPSIZE, MSG_TRUNC, NULL, NULL);

  /* check errors */
  if ( bytes == -1 ){
    if ( errno == EAGAIN ){
      return 0;
    }
    int save = errno;
    logmsg(stderr, "recvfrom() failed with code %d: %s\n", save, strerror(save));
    errno = save;
    return -1;
  }

  /* grab timestamp */
  ioctl(sd, SIOCGSTAMP, &timestamp );

  return bytes;
}

/* This is the RAW_SOCKET capturer..   */ 
void* capture(void* ptr){
  struct CI* CI = (struct CI*)ptr;
  struct raw_context cap;
  
  /* initialize raw capture */
  logmsg(verbose, "CI[%d] initializing capture on %s using RAW_SOCKET (memory at %p).\n", CI->id, CI->nic, &datamem[CI->id]);
  cap.socket = CI->sd;

  /* setup callbacks */
  cap.base.read_packet = (read_packet_callback)read_packet_raw;

  /* start capture */
  capture_loop(CI, (struct capture_context*)&cap);

  /* stop capture */
  logmsg(verbose, "CI[%d] stopping capture on %s.\n", CI->id, CI->nic);

  return NULL;
}
