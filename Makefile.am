ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mp

noinst_LIBRARIES = libcapture.a

libcapture_a_CFLAGS = -Wall ${libcap_utils_CFLAGS} ${PTHREAD_CFLAGS}  ${DAG_CFLAGS}
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

mp_CFLAGS = -Wall ${libcap_utils_CFLAGS} ${libcap_marc_CFLAGS} ${PTHREAD_CFLAGS} ${PCAP_CFLAGS} ${DAG_CFLAGS}
mp_LDADD = libcapture.a ${libcap_utils_LIBS} ${libcap_marc_LIBS} ${PTHREAD_LIBS} ${PCAP_LIBS} ${DAG_LIBS}
mp_SOURCES = \
	configfile.c configfile.h \
	control.c \
	filter.c filter.h \
	headers.h \
	local.c \
	log.h \
	ma.c ma.h \
	main.c \
	sender.c sender.h \
	thread.c thread.h

if BUILD_SEM_TIMEDWAIT
mp_SOURCES += lib/sem_timedwait.c
endif

if SETCAP
setcap:
	$(SETCAP) cap_net_raw+ep $(DESTDIR)$(bindir)/`echo mp | sed '$(program_transform_name)'`
	chmod o-rws $(DESTDIR)$(bindir)/`echo mp | sed '$(program_transform_name)'`
endif

if SETCAP
install-exec-hook: setcap
else
install-exec-hook:
	@echo "ignoring setcap, use \`--enable-setcap-install' to enable."
endif

debpkgname=mp_@VERSION@_@ARCH@

deb: all
	@test "x${prefix}" = "x/usr" || (echo "Error: --prefix must be /usr when creating debian release (currently ${prefix})"; exit 1)
	mkdir -p $(debpkgname)/DEBIAN
	cp dist/deb-control $(debpkgname)/DEBIAN/control
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	dpkg-deb --build $(debpkgname)

EXTRA_DIST = mp.conf.sample
