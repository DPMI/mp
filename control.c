/***************************************************************************
                          Control.c  -  description
                             -------------------
    begin                : Wed Jul 7 2004
    copyright            : (C) 2004-2005 by Patrik Arlos
    email                : patrik.arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
  This thread handles the control of the MP and the communications with the MAC.

 ***************************************************************************/ 

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "capture.h"
#include "filter.h"
#include "log.h"

#include <libmarc/libmarc.h>
#include <stdlib.h>
#include <string.h>
//#//include <stdarg.h>
//#//include <strings.h>
#include <signal.h>
#include <ctype.h>
//#//include <assert.h>
#include <errno.h>

#define STATUS_INTERVAL 60

static void CIstatus(int sig); // Runs when ever a ALRM signal is received.

static marc_context_t client = NULL;

static void mp_auth(struct MPauth* event){
  if( strlen(event->MAMPid) > 0 ){
    MAMPid = strdup(event->MAMPid);
    logmsg(stdout, "MP has been authorized as \"%s\".\n", MAMPid);
  } else {
    logmsg(stdout, "This is a unauthorized MP.\n");
  }
}

static void mp_filter(struct MPFilter* event){
  if( strcmp(event->MAMPid, MAMPid) != 0){
    fprintf(stderr, "This reply was intened for a different MP (%s).\n", event->MAMPid);
    return;
  }

  struct FPI* rule = malloc(sizeof(struct FPI));
  marc_filter_unpack(&event->filter, &rule->filter);

  /* Make sure that the User doesnt request more information than we can give. */
  if ( rule->filter.CAPLEN > PKT_CAPSIZE ){
    rule->filter.CAPLEN = PKT_CAPSIZE;
  }

  logmsg(stdout, "Updating filter {%d}\n", rule->filter.filter_id);
  setFilter(rule);
  if ( verbose_flag ){
    marc_filter_print(stdout, &rule->filter, 0);
  }
}

/**
 * Reload filter.
 * @param id Filter id or -1 for all.
 */
static void mp_filter_reload(int id){
  if ( id == -1 ){
    struct FPI* cur = myRules;
    while ( cur ){
      logmsg(verbose, "Requesting filter {%02d} from MArCd.\n", id);
      marc_filter_request(client, MAMPid, cur->filter.filter_id);
      cur = cur->next;
    }
    return;
  } else {
    logmsg(verbose, "Requesting filter {%02d} from MArCd.\n", id);
    marc_filter_request(client, MAMPid, id);
  }
}

static void mp_filter_del(int id){
  delFilter(id);
}

/**
 * Dump the content of data as hexadecimal (and its ascii repr.)
 */
static void hexdump(FILE* fp, const char* data, size_t size){
  const size_t align = size + (size % 16);
  fputs("[0000]  ", fp);
  for( int i=0; i < align; i++){
    if ( i < size ){
      fprintf(fp, "%02X ", data[i] & 0xff);
    } else {
      fputs("   ", fp);
    }
    if ( i % 4 == 3 ){
      fputs("   ", fp);
    }
    if ( i % 16 == 15 ){
      fputs("    |", fp);
      for ( int j = i-15; j<=i; j++ ){
	char ch = data[j];

	if ( j >= size ){
	  ch = ' ';
	} else if ( !isprint(data[j]) ){
	  ch = '.';
	}

	fputc(ch, fp);
      }
      fputs("|", fp);
      if ( (i+1) < align){
	fprintf(fp, "\n[%04X]  ", i+1);
      }
    }
  }
  printf("\n");
}

static int is_authorized(){
  return MAMPid != NULL;
}

void* control(void* prt){
  int ret;
  sigset_t saved;

  /* unblock SIGUSR1 */
  {
    sigset_t sigmask;
    sigfillset(&sigmask);
    sigdelset(&sigmask, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &sigmask, &saved);
  }
  

  /* redirect output */
  marc_set_output_handler(logmsg, vlogmsg, stderr, verbose);

  /* setup libmarc */
  struct marc_client_info info;
  info.client_ip = NULL;
  info.client_port = 0;
  info.max_filters = CONSUMERS;
  info.noCI = noCI;
  if ( (ret=marc_init_client(&client, MAnic, &info)) != 0 ){
    fprintf(stderr, "marc_init_client() returned %d: %s\n", ret, strerror(ret));
    exit(1);
  }

  /* restore sigmask */
  {
    pthread_sigmask(SIG_SETMASK, &saved, NULL);
  }

  /* setup status ALRM handler */
  {
    struct itimerval difftime;
    difftime.it_interval.tv_sec = STATUS_INTERVAL;
    difftime.it_interval.tv_usec = 0;
    difftime.it_value.tv_sec = STATUS_INTERVAL;
    difftime.it_value.tv_usec = 0;
    signal(SIGALRM, CIstatus);
    setitimer(ITIMER_REAL, &difftime, NULL);
  }

  /* process messages from MArCd */
  MPMessage event;
  size_t size;
  unsigned int auth_retry = 0;
  while( terminateThreads==0 ){
    struct timeval timeout = {1, 0}; /* 1 sec timeout */

    if ( !is_authorized() && auth_retry >= 15 ){
      logmsg(stderr, "No reply from MArCd (make sure MArCd is running). Resending request.\n");
      marc_client_init_request(client, &info);
      auth_retry = 0;
    }

    /* get next message */
    switch ( (ret=marc_poll_event(client, &event, &size, NULL, &timeout)) ){
    case EAGAIN: /* delivered if using a timeout */
    case EINTR:  /* interuped */
      if ( auth_retry >= 0 ){
	auth_retry++;
      }
      continue;

    case 0: /* success, continue processing */
      /* always handle authorization event */
      if ( event.type == MP_CONTROL_AUTHORIZE_EVENT ){
	break;
      }

      /* only handle other events if authorized */
      if ( !is_authorized() ){
	fprintf(stderr, "MP not authorized, ignoring message of type %d\n", event.type);
	continue;
      }
	
      break;

    default: /* error has been raised */
      fprintf(stderr, "marc_poll_event() returned %d: %s\n", ret, strerror(ret));
      return NULL;
    }

    logmsg(verbose, "Got message %d (%zd bytes) from MArCd.\n", event.type, size);

    /* act */
    switch (event.type) { /* ntohl not needed, called by marc_poll_event */
    case MP_CONTROL_AUTHORIZE_EVENT:
      mp_auth(&event.auth);
      auth_retry = -1;
      break;

    case MP_FILTER_EVENT:
      mp_filter(&event.filter);
      break;

    case MP_FILTER_RELOAD_EVENT:
      mp_filter_reload(ntohl(event.filter_id.id));
      break;

    case MP_FILTER_DEL_EVENT:
      mp_filter_del(ntohl(event.filter_id.id));
      break;

    case MP_FILTER_REQUEST_EVENT:
      mp_filter_reload(ntohl(event.filter_id.id));
      break;

    default:
      printf("Control thread got unhandled event of type %d containing %zd bytes.\n", event.type, size);
      printf("PAYLOAD:\n");
      hexdump(stdout, event.payload, size);    
      break;
    }
  }

  marc_cleanup(client);
  client = NULL;

  return NULL;
}

static void CIstatus(int sig){ // Runs when ever a ALRM signal is received.
  if( MAMPid==0 ){
    logmsg(stderr, "Not authorized. No need to inform MArC about the status.\n");
    return;
  }

  struct MPstatus stat;
  stat.type = MP_STATUS_EVENT;
  strncpy(stat.MAMPid, MAMPid, 16);
  stat.noFilters = ntohl(noRules);
  stat.matched   = ntohl(matchPkts);
  stat.noCI      = ntohl(noCI);
  
  char* dst = stat.CIstats;
  for( int i=0; i < noCI; i++){
    /* OMFG! This string is executed as SQL in MArCd */
    dst += sprintf(dst,", CI%d='%s', PKT%d='%ld', BU%d='%d' ",
		   i, _CI[i].iface,
		   i, _CI[i].pktCnt,
		   i, _CI[i].bufferUsage);
  }
  
  int ret;
  if ( (ret=marc_push_event(client, (MPMessage*)&stat, NULL)) != 0 ){
    logmsg(stderr, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
  }
  
  logmsg(stderr, "Status report for %s\n"
	 "\t%d Filters Present\n"
	 "\t%d Capture Interfaces.\n"
	 "\t%d Packets Matched Filters.\n",
	 MAMPid, noRules,noCI,matchPkts);
  for( int i=0; i < noCI; i++){
    fprintf(verbose, "\tCI[%d]=%s  PKT[%d]=%ld BU[%d]=%d\n",
	   i, _CI[i].iface,
	   i, _CI[i].pktCnt,
	   i, _CI[i].bufferUsage);
  }

  if ( noRules == 0 ){
    logmsg(stderr, "Warning: no filters present.\n");
  }
}
