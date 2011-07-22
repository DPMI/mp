#ifndef _MP_SENDER_H
#define _MP_SENDER_H

#include <semaphore.h>
#define SENDER_BARRIER_TIMEOUT 20

struct send_proc {
  int nics;                         /* How many nics/capture processes will be present*/
  sem_t* semaphore;                 /* Semaphore */
  sem_t* flag;                      /* Flag used to mark that the thread has initialized */
  const char* filename;             /* In local mode it is the filename to store the result in */
};
typedef struct send_proc send_proc_t;

void* sender_caputils(void*); /* default sender using caputils */
void* sender_capfile(void*);  /* local mode: store result into a capfile */

#endif /* _MP_SENDER_H */
