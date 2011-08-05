#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#undef sem_timedwait

#include <semaphore.h>
#include <time.h>
#include <errno.h>

/* workaround for broken LinuxThreads sem_timedwait implementation. */
int __sem_timedwait(sem_t* sem, const struct timespec* abs_timeout){
  int ret = sem_timedwait(sem, abs_timeout);
  errno = ret;
  return ret != 0 ? -1 : 0;
}
