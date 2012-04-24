#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture.h"
#include "sender.h"
#include "log.h"
#include <caputils/filter.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

int setup_capture();

extern pthread_t controlPID;

int ma_mode(sigset_t* sigmask, sem_t* semaphore){
  int ret;
  pthread_t senderPID;
  send_proc_t sender;
  sender.nics = noCI;
  sender.semaphore = semaphore;

  if ( !MPinfo->iface ){
    logmsg(stderr, MAIN, "No MA interface specifed!\n");
    logmsg(stderr, MAIN, "See --help for usage.\n");
    return EINVAL;
  }

  /* initialize sender */
  if ( (ret=thread_create_sync(&senderPID, NULL, sender_caputils, &sender, "sender", NULL, SENDER_BARRIER_TIMEOUT)) != 0 ){
    logmsg(stderr, MAIN, "thread_create_sync() [sender] returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  /* initialize capture (blocking until all capture threads has finished) */
  if ( (ret=setup_capture()) != 0 ){
    logmsg(stderr, MAIN, "setup_capture() returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  /* Initialize MA-controller */
  if ( (ret=thread_create_sync(&controlPID, NULL, control, NULL, "control", NULL, SENDER_BARRIER_TIMEOUT)) != 0 ){
    logmsg(stderr, MAIN, "pthread_create() [controller] returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  /* restore to default signal mask */
  pthread_sigmask(SIG_SETMASK, sigmask, NULL);

  /* wait for capture to end */
  logmsg(verbose, MAIN, "goes to sleep; waiting for threads to finish.\n");
  logmsg(verbose, MAIN, "Waiting for sender thread to finish\n");
  pthread_join( senderPID, NULL);

  for ( int i = 0; i < noCI; i++ )  {
    logmsg(verbose, MAIN, "Waiting for CI[%d] thread to finish\n", i);
    pthread_join(_CI[i].thread, NULL);
  }

  if ( controlPID ){
    logmsg(verbose, MAIN, "Waiting for control thread to finish\n");
    pthread_join(controlPID, NULL);
  }

  logmsg(stderr, MAIN, "Thread awakens, all threads finished. Stopping\n");

  return 0;
}
