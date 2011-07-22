#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

struct thread_data* td;
typedef void* (*start_routine)(struct thread_data* td, void* arg);

void thread_init_finished(struct thread_data* td, int status);

/**
 * Create a pthread in a synchronous way.
 *
 * @param thread see pthread_create(3)
 * @param attr see pthread_create(3)
 * @param func see pthread_create(3) and start_routine.
 * @param arg see pthread_create(3)
 * @param tag Optional name of the thread
 * @param timeout When to give up waiting for thread to initialize.
 * @param seconds How long to wait until giving up.

 * @note Specify either timeout or seconds, timeout takes precedance.
 * @return 0 if successful or errno on errors.
 */
int thread_create_sync(pthread_t* thread, const pthread_attr_t* attr, start_routine func, void* arg, char* tag, struct timespec* timeout, unsigned int seconds);

#endif /* THREAD_H */
