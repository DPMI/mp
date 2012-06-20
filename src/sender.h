#ifndef _MP_SENDER_H
#define _MP_SENDER_H

#include "thread.h"
#include <semaphore.h>
#define SENDER_BARRIER_TIMEOUT 30

struct send_proc {
	int nics;                         /* How many nics/capture processes will be present*/
	sem_t* semaphore;                 /* Semaphore */
	const char* filename;             /* In local mode it is the filename to store the result in */
};
typedef struct send_proc send_proc_t;

void* sender_caputils(struct thread_data* td, void*); /* default sender using caputils */
void* sender_capfile(struct thread_data* td, void*);  /* local mode: store result into a capfile */

#endif /* _MP_SENDER_H */
