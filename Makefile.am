ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mp

noinst_LIBRARIES = libcapture.a

libcapture_a_CFLAGS = -Wall ${CAP_UTILS_CFLAGS} ${PTHREAD_CFLAGS}  ${DAG_CFLAGS}
libcapture_a_SOURCES = capture.c capture.h

if HAVE_PCAP
libcapture_a_SOURCES += capture/pcap.c
endif

if HAVE_RAW
libcapture_a_SOURCES += capture/raw.c
endif

if HAVE_DAG
libcapture_a_SOURCES += capture/dag.c
endif

mp_CFLAGS = -Wall ${CAP_UTILS_CFLAGS} ${LIBMARC_CFLAGS} ${PTHREAD_CFLAGS} ${DAG_CFLAGS}
mp_LDADD = libcapture.a ${CAP_UTILS_LIBS} ${LIBMARC_LIBS} ${PTHREAD_LIBS} ${PCAP_LIBS} ${DAG_LIBS}
mp_SOURCES = \
	configfile.c configfile.h \
	control.c \
	filter.c filter.h \
	headers.h \
	local.c \
	log.c log.h \
	ma.c ma.h \
	main.c \
	sender.c sender.h \
	thread.c thread.h

if SETCAP
setcap:
	$(SETCAP) cap_net_raw+ep $(DESTDIR)$(bindir)/mp
	chmod o-rws $(DESTDIR)$(bindir)/mp
endif

if SETCAP
install-exec-hook: setcap
endif
