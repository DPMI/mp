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

#include <caputils/marc.h>
#include <stdlib.h>
#include <string.h>
//#//include <stdarg.h>
//#//include <strings.h>
#include <signal.h>
#include <ctype.h>
//#//include <assert.h>
#include <errno.h>
#include <stdarg.h>

#define STATUS_INTERVAL 60

static void CIstatus(int sig); // Runs when ever a ALRM signal is received.
static void distress(int sig); /* SIGSEGV, fatal */

static marc_context_t client = NULL;
extern int port;

static void mp_auth(struct MPauth* event){
	if( strlen(event->MAMPid) > 0 ){
		mampid_set((char*)MPinfo->id, event->MAMPid);
		logmsg(stdout, CONTROL, "MP has been authorized as \"%s\".\n", MPinfo->id);
	} else {
		logmsg(stdout, CONTROL, "This is a unauthorized MP.\n");
	}
}

static void mp_filter(struct MPFilter* event, size_t bytes){
	if( strcmp(event->MAMPid, MPinfo->id) != 0){
		logmsg(verbose, CONTROL, "This reply was intened for a different MP (%s).\n", event->MAMPid);
		return;
	}

	if ( debug_flag ){
		logmsg(verbose, CONTROL, "Got MPFilter from MArCd.\n");
		hexdump(verbose, (char*)event, bytes);
	}

	if ( bytes < 200 ){
		logmsg(verbose, CONTROL, "Legacy MPFilter detected\n");
		event->filter.version = 0;
	}

	struct filter filter = {0,};
	filter_unpack(&event->filter, &filter);

	/* Make sure that the User doesnt request more information than we can give. */
	filter.caplen = MIN(filter.caplen, PKT_CAPSIZE);

	logmsg(stderr, CONTROL, "Updating filter {%d}\n", filter.filter_id);

	if ( verbose_flag ){
		filter_print(&filter, stdout, 0);
	}

	mprules_add(&filter);

}

/**
 * Reload filter.
 * @param id Filter id or -1 for all.
 */
static void mp_filter_reload(int id){
	if ( id == -1 ){
		struct rule* cur = mprules();
		while ( cur ){
			logmsg(verbose, CONTROL, "Requesting filter {%02d} from MArCd.\n", cur->filter.filter_id);
			marc_filter_request(client, MPinfo->id, cur->filter.filter_id);
			cur = cur->next;
		}
	} else {
		logmsg(verbose, CONTROL, "Requesting filter {%02d} from MArCd.\n", id);
		marc_filter_request(client, MPinfo->id, id);
	}
}

static void mp_filter_del(int id){
	mprules_del(id);
}

static int is_authorized(){
	/* if the first character is a NULL-terminator (i.e strlen() is 0) it isn't
	 * authorized yet. */
	return MPinfo->id[0] != 0;
}

static int output_wrapper_n(FILE* fp, const char* fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	int ret = vlogmsg(fp, CONTROL, fmt, ap);
	va_end(ap);
	return ret;
}

static int output_wrapper_v(FILE* fp, const char* fmt, va_list ap){
	return vlogmsg(fp, CONTROL, fmt, ap);
}

void* control(struct thread_data* td, void* prt){
	int ret;

	/* redirect output */
	marc_set_output_handler(output_wrapper_n, output_wrapper_v, stderr, verbose);

	/* get version of libcap_utils */
	caputils_version_t cv;
	caputils_version(&cv);

	/* setup libmarc */
	struct marc_client_info info = {0,};
	info.client_ip = NULL;
	info.client_port = port;
	info.max_filters = MAX_FILTERS;
	info.noCI = noCI;
	info.version.caputils.major = cv.major;
	info.version.caputils.minor = cv.minor;
	info.version.caputils.micro = cv.micro;
	info.version.self.major = VERSION_MAJOR;
	info.version.self.minor = VERSION_MINOR;
	info.version.self.micro = VERSION_MICRO;

	info.drivers = 0;
#ifdef HAVE_DRIVER_RAW
	info.drivers |= 1;
#endif
#ifdef HAVE_DRIVER_PCAP
	info.drivers |= 2;
#endif
#if defined(HAVE_DRIVER_DAG) || defined(HAVE_DRIVER_DAG_LEGACY)
	info.drivers |= 4;
#endif

	for ( int i = 0; i < noCI; i++ ){
		strncpy(info.CI[i].iface, _CI[i].iface, 8);
	}

	if ( (ret=marc_init_client(&client, MPinfo->iface, &info)) != 0 ){
		fprintf(stderr, "marc_init_client() returned %d: %s\n", ret, strerror(ret));
		thread_init_finished(td, ret);
		return NULL;
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

	/* Catch SIGSEGV to send a distress signal to MArCd */
	signal(SIGSEGV, distress);

	thread_init_finished(td, 0);

	/* process messages from MArCd */
	MPMessage event;
	size_t size;
	int auth_retry = 0;
	while( terminateThreads==0 ){
		struct timeval timeout = {1, 0}; /* 1 sec timeout */

		if ( !is_authorized() && auth_retry >= 15 ){
			logmsg(stderr, CONTROL, "No reply from MArCd (make sure MArCd is running). Resending request.\n");
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
			if ( event.type == MP_CONTROL_AUTHORIZE_EVENT || event.type == MP_CONTROL_AUTHORIZE_REQUEST ){
				break;
			}

			/* only handle other events if authorized */
			if ( !is_authorized() ){
				logmsg(verbose, CONTROL, "MP not authorized, ignoring message of type %d\n", event.type);
				continue;
			}

			break;

		default: /* error has been raised */
			fprintf(stderr, "marc_poll_event() returned %d: %s\n", ret, strerror(ret));
			return NULL;
		}

		logmsg(verbose, CONTROL, "Got message %d (%zd bytes) from MArCd.\n", event.type, size);

		/* act */
		switch (event.type) { /* ntohl not needed, called by marc_poll_event */
		case MP_CONTROL_AUTHORIZE_EVENT:
			mp_auth(&event.auth);
			auth_retry = -1;
			break;

		case MP_CONTROL_AUTHORIZE_REQUEST:
			logmsg(verbose, CONTROL, "Got an authorization request, asking MArCd for a new authorization message.\n");
			marc_client_init_request(client, &info);
			break;

		case MP_FILTER_EVENT:
			mp_filter(&event.filter, size);
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

		case MP_FILTER_INVALID_ID:
			logmsg(verbose, CONTROL, "Filter request failed: invalid id\n");
			break;

		case MP_CONTROL_TERMINATE_EVENT:
			logmsg(stderr, CONTROL, "Got termination request\n");
			terminateThreads = 1;
			break;

		default:
			logmsg(verbose, CONTROL, "Got unhandled event of type %d containing %zd bytes.\n", event.type, size);
			logmsg(verbose, CONTROL, "PAYLOAD:\n");
			hexdump(verbose, event.payload, size);
			break;
		}
	}

	/* inform MArCd that MP is terminating (properly) */
	{
		MPMessage ev;
		ev.type = MP_CONTROL_TERMINATE_EVENT;
		mampid_set(ev.MAMPid, MPinfo->id);
		if ( (ret=marc_push_event(client, &ev, NULL)) != 0 ){
			logmsg(stderr, CONTROL, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
		}
	}

	marc_cleanup(client);
	client = NULL;

	return NULL;
}

static void CIstatus1(){
	struct MPstatus stat;
	memset(&stat, 0, sizeof(struct MPstatus));
	stat.type = MP_STATUS_EVENT;
	mampid_set(stat.MAMPid, MPinfo->id);
	stat.noFilters = htonl(mprules_count());
	stat.matched   = htonl(MPstats->matched_count);
	stat.noCI      = htonl(noCI);

	char* dst = stat.CIstats;
	for( int i=0; i < noCI; i++){
		/* OMFG! This string is executed as SQL in MArCd */
		dst += sprintf(dst,", CI%d='%s', PKT%d='%ld', BU%d='%d' ",
		               i, _CI[i].iface,
		               i, _CI[i].packet_count,
		               i, _CI[i].buffer_usage);
	}

	int ret;
	if ( (ret=marc_push_event(client, (MPMessage*)&stat, NULL)) != 0 ){
		logmsg(stderr, CONTROL, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
	}
}

static void CIstatus2(){
	MPMessage msg;
	struct MPstatus2* stat = (struct MPstatus2*)&msg.status2;

	memset(stat, 0, sizeof(MPMessage));
	stat->type = MP_STATUS2_EVENT;
	mampid_set(stat->MAMPid, MPinfo->id);

	stat->packet_count = htonl(MPstats->packet_count);
	stat->matched_count = htonl(MPstats->matched_count);
	stat->status = 0;
	stat->noFilters = htonl(mprules_count());
	stat->noCI = noCI;

	for( int i=0; i < noCI; i++){
		strncpy(stat->CI[i].iface, _CI[i].iface, 8);
		stat->CI[i].packet_count  = htonl(_CI[i].packet_count);
		stat->CI[i].matched_count = htonl(_CI[i].matched_count);
		stat->CI[i].buffer_usage  = htonl(_CI[i].buffer_usage);
	}

	int ret;
	if ( (ret=marc_push_event(client, (MPMessage*)stat, NULL)) != 0 ){
		logmsg(stderr, CONTROL, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
	}
}

static void CIstatus(int sig){ // Runs when ever a ALRM signal is received.
	if( !is_authorized() ){
		logmsg(verbose, CONTROL, "Not authorized. No need to inform MArC about the status.\n");
		return;
	}

	/* Legacy status event */
	CIstatus1();

	/* Extended status report */
	CIstatus2();

	/* Logging */
	logmsg(stderr, CONTROL, "Status report for %s\n"
	       "\t%zd Filters present\n"
	       "\t%d Capture Interfaces.\n"
	       "\t%ld Packets received.\n"
	       "\t%ld Packets matched filters.\n",
	       mampid_get(MPinfo->id), mprules_count(), noCI, MPstats->packet_count, MPstats->matched_count);
	for( int i=0; i < noCI; i++){
		fprintf(verbose, "\tCI[%d]=%s  PKT[%d]=%ld  MCH[%d]=%ld  BU[%d]=%d\n",
		        i, _CI[i].iface,
		        i, _CI[i].packet_count,
		        i, _CI[i].matched_count,
		        i, _CI[i].buffer_usage);
	}

	if ( mprules_count() == 0 ){
		logmsg(stderr, CONTROL, "Warning: no filters present.\n");
	}
}

static volatile sig_atomic_t fatal_error_in_progress = 0;
static void distress(int sig){
	MPMessage event;
	int ret;

	/* http://www.gnu.org/s/libc/manual/html_node/Termination-in-Handler.html */
	if ( fatal_error_in_progress ){
		raise(sig);
	}
	fatal_error_in_progress = 1;

	logmsg(stderr, CONTROL, "Catched SIGSEGV, sending distress signal to MArCd before dying.\n");

	event.type = MP_CONTROL_DISTRESS;
	mampid_set(event.MAMPid, MPinfo->id);

	if ( (ret=marc_push_event(client, (MPMessage*)&event, NULL)) != 0 ){
		logmsg(stderr, CONTROL, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
	}

	/* if distress is called, it is a fatal error so lets die here. */
	signal(sig, SIG_DFL);
	raise(sig);
}
