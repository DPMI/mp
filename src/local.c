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

extern int flush_flag;
int setup_capture();

int local_mode(sigset_t* sigmask, sem_t* semaphore, struct filter* filter, const char* destination){
	int ret;
	pthread_t senderPID;
	send_proc_t sender;
	sender.nics = noCI;
	sender.semaphore = semaphore;
	sender.filename = destination;

	if ( !destination ){
		logmsg(stderr, MAIN, "No destination selected, use --output.\n");
		return EINVAL;
	}

	/* initialize sender */
	if ( (ret=thread_create_sync(&senderPID, NULL, sender_caputils, &sender, "sender", NULL, SENDER_BARRIER_TIMEOUT)) != 0 ){
		logmsg(stderr, MAIN, "thread_create_sync() [sender] returned %d: %s\n", ret, strerror(ret));
		return ret;
	}

	/* setup destination */
	int flags = flush_flag ? STREAM_ADDR_FLUSH : 0;
	stream_addr_aton(&filter->dest, destination, STREAM_ADDR_GUESS, flags);
	if ( stream_addr_type(&filter->dest) != STREAM_ADDR_CAPFILE && MPinfo->iface == NULL ){
		logmsg(stderr, MAIN, "stream requires MA interface to be set (-s IFACE or see --help)\n");
		return EINVAL;
	}
	filter_print(filter, verbose, 0);
	mprules_add(filter);

	/* initialize capture */
	if ( (ret=setup_capture()) != 0 ){
		logmsg(stderr, MAIN, "setup_capture() returned %d: %s\n", ret, strerror(ret));
		return 1;
	}

	pthread_sigmask(SIG_SETMASK, sigmask, NULL);

	logmsg(verbose, MAIN, "Main thread goes to sleep; waiting for threads to die.\n");
	logmsg(verbose, MAIN, "Waiting for sender thread\n");
	pthread_join( senderPID, NULL);

	for ( int i = 0; i < noCI; i++ )  {
		logmsg(verbose, MAIN, "Waiting for CI[%d] thread\n", i);
		pthread_join(_CI[i].thread, NULL);
		free(_CI[i].iface);
	}

	logmsg(stderr, MAIN, "Thread awakens, all threads terminated. Stopping\n");
	return 0;
}
