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
AM_INIT_AUTOMAKE([-Wall foreign])
AM_SILENT_RULES([yes])
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

ax_dag="no"
ax_dag_legacy="no"

AC_ARG_WITH([raw], [AS_HELP_STRING([--with-raw], [raw packet capture @<:@default=enabled@:>@])])
AC_ARG_WITH([pcap], [AS_HELP_STRING([--with-pcap], [support for pcap (tcpdump) @<:@default=disabled@:>@])])
AC_ARG_WITH([dag], [AS_HELP_STRING([--with-endace-dag@<:@=PATH@:>@], [support for endace DAG-cards @<:@default=disabled@:>@])], [
        ax_dag="yes"
	AX_DAG([$withval])
	AC_DEFINE([HAVE_DRIVER_DAG], 1, [Define to 1 if you have Endace DAG new API])	
])
AC_ARG_WITH([dag-legacy], [AS_HELP_STRING([--with-endace-dag-legacy@<:@=PATH@:>@], [support for endace DAG-cards (using deprecated API) @<:@default=disabled@:>@])], [
        ax_dag_legacy="yes"
	AX_DAG([$withval])
	AC_DEFINE([HAVE_DRIVER_DAG_LEGACY], 1, [Define to 1 if you have Endace DAG deprecated API])	
])

AS_IF([test "x$with_raw" != "xno"], [
	AC_DEFINE([HAVE_DRIVER_RAW], 1, [Define to 1 if you want raw packet capture])
])

AS_IF([test "x$with_pcap" == "xyes"], [
	AC_CHECK_HEADER([pcap/pcap.h], [
		AC_CHECK_LIB([pcap], [pcap_close], [
			AC_DEFINE([HAVE_DRIVER_PCAP], 1, [Define to 1 if you have libpcap])
 			PCAP_LIBS="-lpcap"
        	],[
			AC_MSG_ERROR([Make sure libpcap is available])
        	])
	], [
		AC_MSG_ERROR([Make sure libpcap is available])       
	])
])
AC_SUBST(PCAP_LIBS)

dnl New and legacy DAG API is mutually exclusive.
AS_IF([test "x$ax_dag" == "xyes" -a "x$ax_dag_legacy" == "xyes"], [
	AC_MSG_ERROR([Cannot enable both new and legacy DAG API at the same time.])
])

AC_ARG_WITH([max-packet-age], [AS_HELP_STRING([--with-max-packet-age=MS], [set the maximum time (in ms) a packet can be kept in the sender buffers. @<:@default=800@:>@])])
AS_IF([test "x$with_max_packet_age" != "x"],
	[AC_DEFINE_UNQUOTED([MAX_PACKET_AGE], $with_max_packet_age, [Max packet age])],
	[AC_DEFINE([MAX_PACKET_AGE], 800, [Max packet age])]
)

AC_OUTPUT
