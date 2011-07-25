#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "log.h"
#include <time.h>
#include <sys/time.h>

int verbose_flag = 0;
FILE* verbose = NULL; 

const char* MAIN = "main";
const char* SENDER = "sender";
const char* CAPTURE = "capture";
const char* CONTROL = "control";
const char* FILTER = "filter";

int vlogmsg(FILE* fp, const char* tag, const char* fmt, va_list ap){
  struct timeval tid1;
  gettimeofday(&tid1,NULL);

  struct tm *dagtid;  
  dagtid=localtime(&tid1.tv_sec);

  char time[20] = {0,};  
  strftime(time, sizeof(time), "%Y-%m-%d %H.%M.%S", dagtid);
  
  fprintf(fp, "[%s] [%8s ] ", time, tag);
  return vfprintf(fp, fmt, ap);
}

int logmsg(FILE* fp, const char* tag, const char* fmt, ...){
  va_list ap;
  va_start(ap, fmt);
  int ret = vlogmsg(fp, tag, fmt, ap);
  va_end(ap);
  return ret;
}
