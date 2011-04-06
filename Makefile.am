ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = mp

mp_CFLAGS = -Wall ${CAP_UTILS_CFLAGS} ${LIBMARC_CFLAGS} ${MYSQL_CLIENT_CFLAGS} ${PTHREAD_CFLAGS}
mp_LDADD = ${CAP_UTILS_LIBS} ${LIBMARC_LIBS} ${MYSQL_CLIENT_LIBS} ${PTHREAD_LIBS} ${PCAP_LIBS}
mp_SOURCES = \
	capture.c capture.h \
	control.c \
	filter.c \
	headers.h \
	main.c \
	sender.c
