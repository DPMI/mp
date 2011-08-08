m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [1])

AC_PREREQ([2.61])
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
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_GNU_SOURCE
AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_RANLIB
AX_PTHREAD
AX_BROKEN_SEM_TIMEDWAIT
AM_CONDITIONAL(BUILD_SEM_TIMEDWAIT, [test "x$build_sem_timedwait" == "xyes"])

AC_SEARCH_LIBS([clock_gettime], [rt])
PKG_CHECK_MODULES([libcap_stream], [cap_stream >= 0.7.3])
PKG_CHECK_MODULES([libmarc], [libmarc >= 0.7.0])

ax_dag="no"
ax_dag_legacy="no"

AC_ARG_WITH([raw],  [AS_HELP_STRING([--with-raw], [raw packet capture @<:@default=enabled@:>@])])
AC_ARG_WITH([pcap], [AS_HELP_STRING([--with-pcap], [support for pcap (tcpdump) @<:@default=disabled@:>@])])
AC_ARG_WITH([dag],  [AS_HELP_STRING([--with-dag@<:@=PATH@:>@], [support for endace DAG-cards @<:@default=disabled@:>@])], [
        ax_dag="yes"
	AX_DAG([$withval])
	AC_DEFINE([HAVE_DRIVER_DAG], 1, [Define to 1 if you have Endace DAG new API])	
])
AC_ARG_WITH([dag-legacy], [AS_HELP_STRING([--with-dag-legacy@<:@=PATH@:>@], [support for endace DAG-cards (using deprecated API) @<:@default=disabled@:>@])], [
        ax_dag_legacy="yes"
	AX_DAG([$withval])
	AC_DEFINE([HAVE_DRIVER_DAG_LEGACY], 1, [Define to 1 if you have Endace DAG deprecated API])	
])

AS_IF([test "x$with_raw" != "xno"], [
	AC_DEFINE([HAVE_DRIVER_RAW], 1, [Define to 1 if you want raw packet capture])
])
AM_CONDITIONAL(HAVE_RAW, [test "x$with_raw" != "xno"])

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
AM_CONDITIONAL(HAVE_PCAP, [test "x$with_pcap" == "xyes"])
AC_SUBST(PCAP_LIBS)

dnl Check for setcap
AC_PATH_PROG(SETCAP, setcap,,"/sbin:$PATH")
AC_ARG_ENABLE(setcap-install, AS_HELP_STRING( [--enable-setcap-install], [install mp with cap_net_raw capability @<:@default=no@:>@]))
AS_IF([test "x$enable_setcap_install" == "xyes"], [
	AS_IF([test -z "$SETCAP"], [AC_MSG_ERROR([Could not find setcap, make sure it is installed or disable setcap install.])])
])
AM_CONDITIONAL(SETCAP, test x$enable_setcap_install = "xyes")

dnl New and legacy DAG API is mutually exclusive.
AS_IF([test "x$ax_dag" == "xyes" -a "x$ax_dag_legacy" == "xyes"], [
	AC_MSG_ERROR([Cannot enable both new and legacy DAG API at the same time.])
])
AM_CONDITIONAL(HAVE_DAG, [test "x$ax_dag" == "xyes" -o "x$ax_dag_legacy" == "xyes"])

AC_ARG_VAR([MAX_AGE], [set the maximum time (in ms) a packet can be kept in the sender buffers. @<:@default=800@:>@])
AS_IF([test -z "$MAX_AGE"],
	[AC_DEFINE([MAX_PACKET_AGE], 800, [Max packet age])],
	[AC_DEFINE_UNQUOTED([MAX_PACKET_AGE], $MAX_AGE, [Max packet age])]
)

AC_ARG_VAR([PKT_BUFFER], [Size of the capture buffer in bytes. @<:@default=10000@:>@])
AS_IF([test -z "$PKT_BUFFER"],
	[AC_DEFINE([PKT_BUFFER], 10000, [Size of capture buffer])],
	[AC_DEFINE_UNQUOTED([PKT_BUFFER], $PKT_BUFFER, [Size of capture buffer])]
)

AC_ARG_VAR([PKT_CAPSIZE], [Maximum size of a captured packet in bytes. @<:@default=1514@:>@])
AS_IF([test -z "$PKT_CAPSIZE"],
	[AC_DEFINE([PKT_CAPSIZE], 1514, [Maximum size of a captured packet])],
	[AC_DEFINE_UNQUOTED([PKT_CAPSIZE], $PKT_CAPSIZE, [Maximum size of a captured packet])]
)

AC_ARG_VAR([CI_NO], [Number of parallel captures supported at runtime. @<:@default=2@:>@])
AS_IF([test -z "$CI_NO"],
	[AC_DEFINE([CI_NIC], 2, [Number of capture ifaces])],
	[AC_DEFINE_UNQUOTED([CI_NIC], $CI_NO, [Number of capture ifaces])]
)

AC_ARG_VAR([FILTERS], [Max filters. @<:@default=20@:>@])
AS_IF([test -z "$FILTERS"],
	[AC_DEFINE([CONSUMERS], 20, [Max filters])],
	[AC_DEFINE_UNQUOTED([CONSUMERS], $FILTERS, [Max filters])]
)

AC_OUTPUT
