#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "thread.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include <signal.h>

struct thread_data {
	/* init */
	sem_t flag;
	int status;

	/* callback */
	start_routine func;
	void* data;

	/* debug */
	unsigned int thread_id;
	char tag[0];
};

static __thread struct thread_data* self;

/* wrapper */
static void* thread_launcher(struct thread_data* td){
	self = td;
	return td->func(td, td->data);
}

int thread_create_sync(pthread_t* thread, const pthread_attr_t* attr, start_routine func, void* arg, char* tag, struct timespec* timeout, unsigned int seconds){
	static unsigned int thread_counter = 1;

	int ret;
	struct timespec ts;

	/* initialize thread data */
	struct thread_data* td = malloc(sizeof(struct thread_data) + strlen(tag ? tag : "unnamed") + 1);
	td->status = 0;
	td->func = func;
	td->data = arg;
	td->thread_id = thread_counter++;
	strcpy(td->tag, tag ? tag : "unnamed");

	/* initialize flag semaphore used to check thread initialization status */
	if ( sem_init(&td->flag, 0, 0) != 0 ){
		int saved = errno;
		logmsg(stderr, MAIN, "sem_init() [%s] returned %d: %s\n", tag, saved, strerror(saved));
		return saved;
	}

	/* figure out timeout */
	if ( timeout ){
		ts = *timeout;
	} else {
		if ( clock_gettime(CLOCK_REALTIME, &ts) != 0 ){
			int saved = errno;
			logmsg(stderr, MAIN, "clock_gettime() [%s] returned %d: %s\n", tag, saved, strerror(saved));
			return saved;
		}

		ts.tv_sec += seconds;
	}

	/* create thread */
	if ( (ret=pthread_create(thread, attr, (void*(*)(void*))thread_launcher, td)) != 0 ) {
		logmsg(stderr, MAIN, "pthread_create() [%s] returned %d: %s\n", tag, ret, strerror(ret));
		return ret;
	}

	/* wait for thread initialization */
	if ( sem_timedwait(&td->flag, &ts) != 0 ){
		int saved = errno;
		switch ( saved ){
		case ETIMEDOUT:
			if ( pthread_kill(*thread, 0) == ESRCH ){
				logmsg(stderr, MAIN, "sem_timedwait(): [%s] child thread died before completing initialization\n", tag);
			} else {
				logmsg(stderr, MAIN, "sem_timedwait(): [%s] timed out waiting for initialization to finish, but child is still alive\n", tag);
			}
			/* fallthrough */

		case EINTR:
			break;

		default:
			logmsg(stderr, MAIN, "sem_timedwait() [%s] returned %d: %s\n", tag, saved, strerror(saved));
		}
		return saved;
	}

	/* destroy semaphore */
	sem_destroy(&td->flag);

	/* finished */
	return td->status;
}

void thread_init_finished(struct thread_data* td, int status){
	td->status = status;
	if ( sem_post(&td->flag) != 0 ){
		int saved = errno;
		logmsg(stderr, MAIN, "sem_post() [%s] returned %d: %s\n", td->tag, saved, strerror(saved));
	}

	/* give parent thread a chance to continue */
	sched_yield();
}

unsigned int thread_id(){
	return self->thread_id;
}
