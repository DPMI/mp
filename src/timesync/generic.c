#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "timesync.h"
#include "log.h"
#include <string.h>

int timesync_init(struct CI* CI) {
  logmsg(verbose, SYNC, "Init of %s .\n", CI->iface);
  CI->synchronized='U';
  return 1;
}

int timesync_status(struct CI* CI){
  logmsg(stderr,"TIMESYNC", "DAG synchronization not supported.\n");
  CI->synchronized='U';
  return 1;
}
