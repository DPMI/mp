#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture.h"
#include "sender.h"
#include "log.h"
#include <caputils/filter.h>
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
    logmsg(stderr, "No MA interface specifed!\n");
    logmsg(stderr, "See --help for usage.\n");
    return EINVAL;
  }

  /* initialize sender */
  if ( (ret=pthread_create(&senderPID, NULL, sender_caputils, &sender)) != 0 ){
    logmsg(stderr, "pthread_create() [sender] returned %d: %s\n", ret, strerror(ret));
    return ret;
  }
  sem_wait(semaphore); /* sender raises semaphore when ready */

  /* initialize capture */
  if ( (ret=setup_capture()) != 0 ){
    logmsg(stderr, "setup_capture() returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  printf("Waiting 1s befor starting controler thread.\n");
  sleep(1);
  
    /* Initialize MA-controller */
  if ( (ret=pthread_create(&controlPID, NULL, control, NULL)) != 0 ) {
    fprintf(stderr,"pthread_create() [controller] returned %d: %s\n", ret, strerror(ret));
    return ret;
  }

  pthread_sigmask(SIG_SETMASK, sigmask, NULL);

  logmsg(verbose, "Main thread goes to sleep; waiting for threads to die.\n");
  logmsg(verbose, "[MAIN] - Waiting for sender thread\n");
  pthread_join( senderPID, NULL);

  for ( int i = 0; i < noCI; i++ )  {
    logmsg(verbose, "[MAIN] - Waiting for CI[%d] thread\n", i);
    pthread_join(_CI[i].thread, NULL);
  }
  
  if ( controlPID ){
    logmsg(verbose, "[MAIN] - Waiting for control thread\n");
    pthread_join(controlPID, NULL);
  }

  logmsg(stderr, "Main thread awakens, all threads terminated. Stopping\n");

  return 0;
}
