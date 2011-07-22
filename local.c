#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture.h"
#include "filter.h"
#include "sender.h"
#include "log.h"
#include "ma.h"
#include <caputils/filter.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

int setup_capture();

int local_mode(sigset_t* sigmask, sem_t* semaphore, const struct filter* filter, const char* filename){
  int ret;
  pthread_t senderPID;
  send_proc_t sender;
  sem_t flag;
  sender.nics = noCI;
  sender.semaphore = semaphore;
  sender.filename = filename;

  if ( !filename ){
    logmsg(stderr, "No filename selected, use --capfile.\n");
    return EINVAL;
  }

  /* initialize flag semaphore used to check thread initialization status */
  if ( sem_init(&flag, 0, 0) != 0 ){
    int saved = errno;
    logmsg(stderr, "sem_init() [sender] returned %d: %s\n", saved, strerror(saved));
    return saved;
  }

  /* initialize sender */
  if ( (ret=pthread_create(&senderPID, NULL, sender_capfile, &sender)) != 0 ){
    logmsg(stderr, "setup_sender() returned %d: %s\n", ret, strerror(ret));
    return 1;
  }

  /* wait for sender to finish (raises semaphore when ready) */
  if ( (ret=flag_wait(&flag, SENDER_BARRIER_TIMEOUT)) != 0 ){
    logmsg(stderr, "sender_barrier() [local] returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  /* initialize capture */
  mprules_add(filter);
  if ( (ret=setup_capture()) != 0 ){
    logmsg(stderr, "setup_capture() returned %d: %s\n", ret, strerror(ret));
    return 1;
  }

  pthread_sigmask(SIG_SETMASK, sigmask, NULL);

  logmsg(verbose, "Main thread goes to sleep; waiting for threads to die.\n");
  logmsg(verbose, "[MAIN] - Waiting for sender thread\n");
  pthread_join( senderPID, NULL);

  for ( int i = 0; i < noCI; i++ )  {
    logmsg(verbose, "[MAIN] - Waiting for CI[%d] thread\n", i);
    pthread_join(_CI[i].thread, NULL);
  }

  logmsg(stderr, "Main thread awakens, all threads terminated. Stopping\n");
  return 0;
}
