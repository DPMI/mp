m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [0])

AC_INIT([mp],[__VERSION_MAJOR__.__VERSION_MINOR__.__VERSION_MICRO__], [dsv@bth.se])

VERSION_MAJOR=__VERSION_MAJOR__
VERSION_MINOR=__VERSION_MINOR__
VERSION_MICRO=__VERSION_MICRO__

AC_DEFINE_UNQUOTED([VERSION_MAJOR], [${VERSION_MAJOR}], [Major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [${VERSION_MINOR}], [Minor version number])
AC_DEFINE_UNQUOTED([VERSION_MICRO], [${VERSION_MICRO}], [Micro version number])
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])
AC_SUBST([VERSION_MICRO])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall 1.11 silent-rules foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_RANLIB
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
