#ifndef MA_H
#define MA_H

int local_mode(sigset_t* sigmask, sem_t* semaphore, const struct filter* filter, const char* filename);
int ma_mode(sigset_t* sigmask, sem_t* semaphore);

#endif /* MA_H */
