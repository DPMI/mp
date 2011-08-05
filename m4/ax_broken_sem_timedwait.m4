AC_DEFUN([AX_BROKEN_SEM_TIMEDWAIT], [
  saved_LDFLAGS="$LDFLAGS"
  LDFLAGS="-lrt"
  AC_MSG_CHECKING([broken sem_timedwait implementation])  
  AC_RUN_IFELSE([
    AC_LANG_PROGRAM([dnl
      #include <semaphore.h>
      #include <time.h>], [dnl
      sem_t sem;
      struct timespec ts = {0,0};
      sem_init(&sem, 0, 0);
      return sem_timedwait(&sem, &ts) == -1 ? 0 : 1;
    ])
  ],[
    AC_MSG_RESULT([POSIX compliant])
    build_sem_timedwait="no"
  ], [
    AC_MSG_RESULT([broken])
    AC_DEFINE([sem_timedwait], [__sem_timedwait], [workaround for broken sem_timedwait implementations])
    build_sem_timedwait="yes"
  ])
  LDFLAGS="$saved_LDFLAGS"
])
