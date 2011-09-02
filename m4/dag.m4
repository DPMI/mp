AC_DEFUN([AX_DAG2], [
  saved_CPPFLAGS="$CPPFLAGS"

  case $1 in
    yes | "")
      ax_dag_path=
      ax_dag_want="yes"
      ;;
    no)
      ax_dag_want="no"
      ;;
    *)
      ax_dag_path="$1"
      ax_dag_want="yes"
      CPPFLAGS="$CPPFLAGS -I$ax_dag_path/include"
      ;;
  esac

  AS_IF([test "x${ax_dag_want}" == "xyes"], [
    AC_CHECK_HEADER([dagapi.h],[
      dnl defaults
      ax_dag_cflags=
      ax_dag_libs=-ldag

      AS_IF([test "x$ax_dag_path" != "x"], [
        ax_dag_cflags="-I$ax_dag_path/include"
        ax_dag_libs="-L$ax_dag_path/lib $ax_dag_libs"
      ])

      AS_IF([test "x$2" == "xlegacy"], [
        AC_MSG_CHECKING([for dagapi.o])
        AS_IF([test -e $ax_dag_path/tools/dagapi.o], [
          AC_MSG_RESULT([yes])
          dnl assume dagopts.o exists if dagapi.o does
          ax_dag_libs="$ax_dag_path/tools/dagapi.o $ax_dag_path/tools/dagopts.o ${ax_dag_libs}"
        ],[
          AC_MSG_RESULT([no])
          AC_MSG_ERROR([


Legacy drivers require \$prefix/tools/dagapi.o to be present. Point the prefix to the source-tree instead of installed location.
This is because nothing in dagapi.h is implemented in libdag.{s,so} library])
        ])
      ])
      AC_SUBST(DAG_CFLAGS, [$ax_dag_cflags])
      AC_SUBST(DAG_LIBS, [$ax_dag_libs])
      AC_DEFINE([HAVE_DAG], 1, [Define to 1 if you have Endace DAG])
    ], [
      AC_MSG_ERROR([Make sure the Endace DAG drivers are installed.])
    ])
  ]) dnl if ${ax_dag_want}

  CPPFLAGS="$saved_CPPFLAGS"
])
