#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "log.h"
#include <time.h>
#include <sys/time.h>

int verbose_flag = 0;
FILE* verbose = NULL; 

int vlogmsg(FILE* fp, const char* fmt, va_list ap){
  struct timeval tid1;
  gettimeofday(&tid1,NULL);

  struct tm *dagtid;  
  dagtid=localtime(&tid1.tv_sec);

  char time[20] = {0,};  
  strftime(time, sizeof(time), "%Y-%m-%d %H.%M.%S", dagtid);
  
  fprintf(fp, "[%s] ", time);
  return vfprintf(fp, fmt, ap);
}

int logmsg(FILE* fp, const char* fmt, ...){
  va_list ap;
  va_start(ap, fmt);
  int ret = vlogmsg(fp, fmt, ap);
  va_end(ap);
  return ret;
}
