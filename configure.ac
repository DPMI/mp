AC_INIT([mp],[0.6], [dsv@bth.se])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC_C_O
AC_PROG_CC_C99
AX_PTHREAD

AC_SEARCH_LIBS([clock_gettime], [rt])
PKG_CHECK_MODULES([CAP_UTILS], [cap_utils >= 0.7])
PKG_CHECK_MODULES([LIBMARC], [libmarc >= 0.7])

AC_CHECK_HEADER([pcap/pcap.h],
[
        AC_CHECK_LIB([pcap], [pcap_close],
        [
                AC_DEFINE([HAVE_PCAP], 1, [Define to 1 if you have libpcap])
                PCAP_LIBS="-lpcap"
        ],[
                AC_MSG_ERROR([Make sure libpcap is available])
        ])
], [
   AC_MSG_ERROR([Make sure libpcap is available])       
])
AC_SUBST(PCAP_LIBS)

AC_ARG_WITH([endace-dag], [AS_HELP_STRING([--with-endace-dag], [support for endace DAG-cards @<:@default=disabled@:>@])])

AS_IF([test "x$with_endace_dag" == "xyes"], [
	AC_CHECK_HEADER([dagnew.h],
		[AC_DEFINE([HAVE_DAG], 1, [Define to 1 if you have Endace DAG])],
		[AC_MSG_ERROR([Make sure the Endace DAG drivers are installed.])]
	)]
)

AC_OUTPUT
