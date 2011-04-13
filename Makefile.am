ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mp

noinst_LIBRARIES = libcapture.a

libcapture_a_CFLAGS = -Wall ${CAP_UTILS_CFLAGS} ${PTHREAD_CFLAGS}
libcapture_a_SOURCES = capture.c capture.h \
	capture/pcap.c \
	capture/raw.c

mp_CFLAGS = -Wall ${CAP_UTILS_CFLAGS} ${LIBMARC_CFLAGS} ${PTHREAD_CFLAGS}
mp_LDADD = libcapture.a ${CAP_UTILS_LIBS} ${LIBMARC_LIBS} ${PTHREAD_LIBS} ${PCAP_LIBS}
mp_SOURCES = \
	control.c \
	filter.c \
	headers.h \
	log.c \
	main.c \
	sender.c
