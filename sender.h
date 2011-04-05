#ifndef _MP_SENDER_H
#define _MP_SENDER_H

struct send_proc {
  int nics;                         /* How many nics/capture processes will be present*/
  char *nic;                        /* The names of these */
  sem_t* semaphore;                 /* Semaphore */
};
typedef struct send_proc send_proc_t;

#endif /* _MP_SENDER_H */
