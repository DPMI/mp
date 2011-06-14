AC_DEFUN([AX_DAG], [
  saved_CPPFLAGS="$CPPFLAGS"

  case $1 in
    yes | "")
      ax_dag_path=
      ;;
    *)
      ax_dag_path="$1"
      CPPFLAGS="$CPPFLAGS -I$ax_dag_path/include"
      ;;
  esac

  AC_CHECK_HEADER([dagapi.h],[
    AS_IF([test "x$ax_dag_path" != "x"], [
      AC_SUBST(DAG_CFLAGS, [-I$ax_dag_path/include])
      AC_SUBST(DAG_LIBS, ["-L$ax_dag_path/lib -ldag"])
    ], [
      AC_SUBST(DAG_CFLAGS, [])
      AC_SUBST(DAG_LIBS, [-ldag])
    ])
    AC_DEFINE([HAVE_DAG], 1, [Define to 1 if you have Endace DAG])
  ], [
    AC_MSG_ERROR([Make sure the Endace DAG drivers are installed.])
  ])

  CPPFLAGS="$saved_CPPFLAGS"
])
