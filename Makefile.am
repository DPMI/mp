ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mp mp-smoke
noinst_LIBRARIES = libcapture.a
pkgconf_DATA = mp.conf.sample

libcapture_a_CFLAGS = -I ${top_srcdir}/src -Wall ${libcap_utils_CFLAGS} ${PTHREAD_CFLAGS} ${DAG_CFLAGS}
libcapture_a_SOURCES = src/capture.c src/capture.h

if HAVE_PCAP
libcapture_a_SOURCES += src/capture/pcap.c
endif

if HAVE_RAW
libcapture_a_SOURCES += src/capture/raw.c
endif

if HAVE_DAG
libcapture_a_SOURCES += src/capture/dag.c
endif

mp_CFLAGS = -I ${top_srcdir}/src -Wall ${libcap_utils_CFLAGS} ${PTHREAD_CFLAGS} ${PCAP_CFLAGS} ${DAG_CFLAGS}
mp_LDADD = libcapture.a -ldl ${libcap_utils_LIBS} ${PTHREAD_LIBS} ${PCAP_LIBS} ${DAG_LIBS} ${DAG_CONF_LIBS}
mp_SOURCES = \
	src/configfile.c src/configfile.h \
	src/control.c \
	src/destination.c src/destination.h \
	src/filter.c src/filter.h \
	src/local.c \
	src/log.h \
	src/ma.c src/ma.h \
	src/main.c \
	src/sender.c src/sender.h \
	src/thread.c src/thread.h \
	src/timesync.h

if BUILD_SEM_TIMEDWAIT
mp_SOURCES += lib/sem_timedwait.c
endif

if HAVE_DAG
mp_SOURCES += src/timesync/dag.c
else
mp_SOURCES += src/timesync/generic.c
endif

mp_smoke_SOURCES = src/mpsmoke.c
mp_smoke_CFLAGS = ${libcap_utils_CFLAGS}
mp_smoke_LDADD = ${libcap_utils_LIBS}

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
	@test "x${sysconfdir}" = "x/etc" || (echo "Error: --sysconfdir must be /etc when creating debian release (currently ${sysconfdir})"; exit 1)
	mkdir -p $(debpkgname)/DEBIAN
	cp dist/deb-control $(debpkgname)/DEBIAN/control
	$(MAKE) install DESTDIR=`pwd`/$(debpkgname)
	dpkg-deb --build $(debpkgname)

EXTRA_DIST = mp.conf.sample
