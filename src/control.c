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
#include "timesync.h"

#include <caputils/marc.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <dlfcn.h>


#define STATUS_INTERVAL 60

static void CIstatus(int sig); // Runs when ever a ALRM signal is received.
static void distress(int sig); /* SIGSEGV, fatal */
void set_local_mampid(mampid_t mampid);
void update_local_mtu();

static marc_context_t client = NULL;
extern int port;
extern char* marc_ip;

static void mp_auth(struct MPauth* event){
	if( strlen(event->MAMPid) > 0 ){
		set_local_mampid(event->MAMPid);
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
	filter.caplen = MIN(filter.caplen, snaplen());

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
	info.server_ip = marc_ip;
	info.client_port = port;
	info.max_filters = MAX_FILTERS;
	info.noCI = noCI;
	info.ma_mtu = MPinfo->MTU;
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
	logmsg(verbose, CONTROL, "Listening on %s:%d.\n", info.client_ip, info.client_port);

	/* setup status ALRM handler */
	{
		/* unblock SIGALRM in case it was blocked (LinuxThreads seems to inhibit this behaviour) */
		sigset_t sigmask;
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGALRM);
		pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);

		/* timer */
		struct itimerval difftime;
		difftime.it_interval.tv_sec = STATUS_INTERVAL;
		difftime.it_interval.tv_usec = 0;
		difftime.it_value.tv_sec = STATUS_INTERVAL;
		difftime.it_value.tv_usec = 0;
		signal(SIGALRM, CIstatus);
		setitimer(ITIMER_REAL, &difftime, NULL);
	}

	/* Catch various signals to send a distress signal to MArCd */
	signal(SIGSEGV, distress);
	signal(SIGBUS, distress);
	signal(SIGILL, distress);

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
		switch ( (ret=marc_poll_event(client, &event, &size, NULL, NULL, &timeout)) ){
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

		if ( debug_flag ){
			logmsg(verbose, CONTROL, "Got message %d (%zd bytes) from MArCd.\n", event.type, size);
		}

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
			logmsg(verbose, CONTROL, "Got unhandled event of type %d containing %zd bytes (including header).\n", event.type, size);
			logmsg(verbose, CONTROL, "PAYLOAD (%zd bytes):\n", size-4-sizeof(mampid_t));
			hexdump(verbose, event.payload, size-4-sizeof(mampid_t));
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

static void CIstatusExtended(){
	MPMessage msg;
	struct MPstatusExtended* stat = &msg.status;

	update_local_mtu();

	memset(stat, 0, sizeof(MPMessage));
	stat->type = MP_STATUS3_EVENT;
	stat->version = 2;
	stat->MTU = htons(MPinfo->MTU);
	mampid_set(stat->MAMPid, MPinfo->id);

	/* reset counters */
	MPstats->packet_count = 0;
	MPstats->matched_count = 0;
	MPstats->dropped_count = 0;

	for( int i=0; i < noCI; i++){
		const float BU = (float)buffer_utilization(&_CI[i]) / PKT_BUFFER;
		MPstats->packet_count  += _CI[i].packet_count;
		MPstats->matched_count += _CI[i].matched_count;
		MPstats->dropped_count += _CI[i].dropped_count;

		strncpy(stat->CI[i].iface, _CI[i].iface, 8);
		stat->CI[i].packet_count  = htonl(_CI[i].packet_count);
		stat->CI[i].matched_count = htonl(_CI[i].matched_count);
		stat->CI[i].dropped_count = htonl(_CI[i].dropped_count);
		stat->CI[i].buffer_usage  = htonl((int)(BU*1000)); /* sent as 1000 steps so receiver can parse percent with one decimal */
		//		stat->CI[i].sync=0; /* -1, not synced, 0 - unknonw, 1 - synced */
		//		logmsg(verbose,"CONTROL", "Status of device : %s ", _CI[i].iface);
		timesync_status(&_CI[i]);
	}

	stat->packet_count  = htonl(MPstats->packet_count);
	stat->matched_count = htonl(MPstats->matched_count);
	stat->dropped_count = htonl(MPstats->dropped_count);
	stat->status = 0;
	stat->noFilters = mprules_count();
	stat->noCI = noCI;

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

	//Populate statistics.
	CIstatusExtended();

	/* Compare with previous stats */
	static struct MPstats prev = {0,};
	struct MPstats delta = {
		.packet_count  = MPstats->packet_count  - prev.packet_count,
		.matched_count = MPstats->matched_count - prev.matched_count,
		.dropped_count = MPstats->dropped_count - prev.dropped_count,
	};
	prev = *MPstats;

	/* Logging */
	logmsg(stderr, CONTROL, "Status report for %s\n"
	       "\t%zd Filters present\n"
	       "\t%d Capture Interfaces.\n"
	       "\t%ld Packets received (%ld new).\n"
	       "\t%ld Packets matched (%ld new).\n"
	       "\t%ld Packets dropped (%ld new).\n",
	       mampid_get(MPinfo->id), mprules_count(), noCI,
	       MPstats->packet_count, delta.packet_count,
	       MPstats->matched_count, delta.matched_count,
	       MPstats->dropped_count, delta.dropped_count);

	char* last_tick;
	for( int i=0; i < noCI; i++){
		const int u = buffer_utilization(&_CI[i]);
		const float BU = (float)u / PKT_BUFFER;
		fprintf(stderr, "\tCI[%d]=%s  PKT=%ld  MCH=%ld  DRP=%ld BU=%.1f%% (%d of %d)\n", i,
		        _CI[i].iface,
		        _CI[i].packet_count,
		        _CI[i].matched_count,
		        _CI[i].dropped_count,
		        BU*100.0f, u, PKT_BUFFER);
		// Handle syncronization status
		
		if(_CI[i].synchronized=='N'){
		  fprintf(stderr,"\tNot Synchronized: ");
		} else if (_CI[i].synchronized=='Y'){
		  fprintf(stderr,"\tSynchronized: ");
		} else {
		  fprintf(stderr,"\tUndefined: ");
		}
		fprintf(stderr," Frequency %dHz \n",_CI[i].frequency);
		last_tick = ctime(&_CI[i].hosttime);
		fprintf(stderr,"\tHost:%s", last_tick);
		last_tick = ctime(&_CI[i].citime);
		fprintf(stderr,"\tCI:%s", last_tick);
		/*
		if(strncmp(_CI[i].iface,"dag",3)==0){
		  
		} else {

		}
		*/
		fprintf(stderr,"\n");
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

	logmsg(stderr, CONTROL, "\n\n\n-----------------------------------------------------------------------------------------------\n");

	if ( sig > 0 ){
		logmsg(stderr, CONTROL, "Got fatal signal (%d), sending distress signal to MArCd before dying.\n", sig);
	} else {
		logmsg(stderr, CONTROL, "Assertion fired, sending distress signal to MArCd before dying.\n");
		logmsg(stderr, CONTROL, "Got %d .\n", sig);
	}

	extern char commandline[];
	logmsg(stderr, CONTROL, "  This is a bug. Please report it to \n");
	logmsg(stderr, CONTROL, "  " PACKAGE_BUGREPORT "\n");
	logmsg(stderr, CONTROL, "\n");
	logmsg(stderr, CONTROL, "  Make sure you include:\n");
	logmsg(stderr, CONTROL, "    - the full message,\n");
	logmsg(stderr, CONTROL, "    - a short description of what happened,\n");
	logmsg(stderr, CONTROL, "    - compiler version (e.g. gcc --version),\n");
	logmsg(stderr, CONTROL, "    - libc version (e.g. ldd --version),\n");
	logmsg(stderr, CONTROL, "    - kernel version (e.g. uname -a),\n");
	logmsg(stderr, CONTROL, "    - MP-" VERSION " (caputils-%s)\n",  caputils_version(NULL));
	logmsg(stderr, CONTROL, "    - commandline: %s\n", commandline);
	logmsg(stderr, CONTROL, "    - if possible, use gdb and execute `bt' and `info threads'.\n");
	logmsg(stderr, CONTROL, "\n");
	logmsg(stderr, CONTROL, "  If using git please include the output of the following commands:\n");
	logmsg(stderr, CONTROL, "    - git status --short --porcelain\n");
	logmsg(stderr, CONTROL, "    - git rev-parse --short HEAD\n");
	logmsg(stderr, CONTROL, "    - git rev-parse --abbrev-ref HEAD\n");

	event.type = MP_CONTROL_DISTRESS;
	mampid_set(event.MAMPid, MPinfo->id);

	if ( (ret=marc_push_event(client, (MPMessage*)&event, NULL)) != 0 ){
		logmsg(stderr, CONTROL, "marc_push_event() returned %d: %s\n", ret, strerror(ret));
	}

	/* if distress is called, it is a fatal error so lets die here. */
	if ( sig != 0 ){
		signal(sig, SIG_DFL);
		raise(sig);
	}
}

/**
 * Override assertion function from glibc to send distress signal to MArCd.
 */
void __assert_fail(const char* expr, const char* filename, unsigned int line, const char* func){
	distress(0);

	logmsg(stderr, CONTROL, "\n");
	logmsg(stderr, CONTROL, "  Message:\n");

	void (*real)(const char*, const char*, unsigned int, const char*) = dlsym(RTLD_NEXT, "__assert_fail");
	if ( real ){
		real(expr, filename, line, func);
	} else {
		fprintf(stderr, "mp:asdf %s:%d: %s: Assertion `%s' failed.\n", filename, line, func, expr);
		abort();
	}
}
