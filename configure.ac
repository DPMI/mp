m4_define([__VERSION_MAJOR__], [0])
m4_define([__VERSION_MINOR__], [7])
m4_define([__VERSION_MICRO__], [10])
m4_define([__VERSION_SUFFIX__], [-git])

AC_PREREQ([2.61])
AC_INIT([mp], m4_join([],m4_join([.], __VERSION_MAJOR__, __VERSION_MINOR__, __VERSION_MICRO__), __VERSION_SUFFIX__), [dsv@bth.se])

VERSION_MAJOR=__VERSION_MAJOR__
VERSION_MINOR=__VERSION_MINOR__
VERSION_MICRO=__VERSION_MICRO__
VERSION_SUFFIX=__VERSION_SUFFIX__

AC_DEFINE_UNQUOTED([VERSION_MAJOR],  [${VERSION_MAJOR}], [Major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR],  [${VERSION_MINOR}], [Minor version number])
AC_DEFINE_UNQUOTED([VERSION_MICRO],  [${VERSION_MICRO}], [Micro version number])
AC_DEFINE_UNQUOTED([VERSION_SUFFIX], ["${VERSION_SUFFIX}"], [Suffix of package (e.g. git)])
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])
AC_SUBST([VERSION_MICRO])
AC_SUBST([VERSION_SUFFIX])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile dist/deb-control])

AC_GNU_SOURCE
AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_RANLIB
AX_PTHREAD
AX_BROKEN_SEM_TIMEDWAIT
AM_CONDITIONAL(BUILD_SEM_TIMEDWAIT, [test "x$build_sem_timedwait" == "xyes"])
AC_ARG_PROGRAM

pkgconfdir="${sysconfdir}/mp"
AC_SUBST(pkgconfdir)
AX_DEFINE_DIR([PKGCONF_DIR], [pkgconfdir], [mp configuration files])

AC_SEARCH_LIBS([clock_gettime], [rt])
PKG_CHECK_MODULES([libcap_utils], [libcap_utils-0.7 >= 0.7.10 libcap_marc-0.7])

ax_dag="no"
ax_dag_legacy="no"

AC_ARG_WITH([raw],  [AS_HELP_STRING([--with-raw], [raw packet capture @<:@default=enabled@:>@])])
AC_ARG_WITH([pcap], [AS_HELP_STRING([--with-pcap], [support for pcap (tcpdump) @<:@default=enabled@:>@])])
AC_ARG_WITH([dag],  [AS_HELP_STRING([--with-dag@<:@=PATH@:>@], [support for endace DAG-cards @<:@default=disabled@:>@])], [
  AS_IF([test "x$withval" != "xno"], [
    ax_dag="yes"
	  AX_DAG2([$withval])
    AC_DEFINE([HAVE_DRIVER_DAG], 1, [Define to 1 if you have Endace DAG new API])
  ])
])
AC_ARG_WITH([dag-legacy], [AS_HELP_STRING([--with-dag-legacy@<:@=PATH@:>@], [support for endace DAG-cards (using deprecated API) @<:@default=disabled@:>@])], [
  AS_IF([test "x$withval" != "xno"], [
    ax_dag_legacy="yes"
  	AX_DAG2([$withval], [legacy])
  	AC_DEFINE([HAVE_DRIVER_DAG_LEGACY], 1, [Define to 1 if you have Endace DAG deprecated API])
  ])
])

AS_IF([test "x$with_raw" != "xno"], [
	AC_DEFINE([HAVE_DRIVER_RAW], 1, [Define to 1 if you want raw packet capture])
])
AM_CONDITIONAL(HAVE_RAW, [test "x$with_raw" != "xno"])

AS_IF([test "x$with_pcap" != "xno"], [
	AC_CHECK_HEADER([pcap.h], [
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
AM_CONDITIONAL(HAVE_PCAP, [test "x$with_pcap" != "xno"])
AC_SUBST(PCAP_LIBS)

dnl Check for setcap
AC_PATH_PROG(SETCAP, setcap,,"/sbin:$PATH")
AC_ARG_ENABLE(setcap-install, AS_HELP_STRING( [--enable-setcap-install], [install mp with cap_net_raw capability @<:@default=no@:>@]))
AS_IF([test "x$enable_setcap_install" == "xyes"], [
	AS_IF([test -z "$SETCAP"], [AC_MSG_ERROR([Could not find setcap, make sure it is installed or disable setcap install.])])
])
AM_CONDITIONAL(SETCAP, test x$enable_setcap_install = "xyes")
AC_SUBST(program_transform_name)

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
	[AC_DEFINE([MAX_FILTERS], 20, [Max filters])],
	[AC_DEFINE_UNQUOTED([MAX_FILTERS], $FILTERS, [Max filters])]
)

dnl Find out what arch is used for (debian) packaging.
ARCH=`echo $host|cut -d '-' -f 1`
AS_IF([test "$ARCH" = "i686"], [ARCH="i386"])
AS_IF([test "$ARCH" = "x86_64"], [ARCH="amd64"])
AC_SUBST(ARCH)

AC_OUTPUT
