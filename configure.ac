#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([pam_2fa], [1.0], [Computer.Security@cern.ch])
AC_CONFIG_SRCDIR([pam_2fa.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

# Enable locals like _GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT

AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h syslog.h unistd.h])
AC_CHECK_HEADERS([security/pam_appl.h] [security/pam_modules.h] [security/pam_ext.h] [security/pam_modutil.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install pam-devel/libpam-dev.]])])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([asprintf bzero dup2 gethostname memset memmove strchr strdup strrchr strstr])

# PAM
AC_CHECK_LIB([pam], [pam_start])

case "$build_os" in
freebsd*)
  AC_SUBST(PAMDIR, "\${exec_prefix}/usr/local/lib")

  if ( test -z ${PKG_CONFIG}); then
    PKG_CONFIG=/usr/local/bin/pkg-config
  fi
  ;;
*)
  AC_SUBST(PAMDIR, "\${exec_prefix}/lib/security")
  ;;
esac

AC_ARG_WITH(
  [pam-dir],
  AC_HELP_STRING(
    [--with-pam-dir=DIR],
    [Where to install PAM module [[PREFIX/lib/security]]]
  ),
  [
    case "${withval}" in
    /*) PAMDIR="${withval}";;
    ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
    *) PAMDIR="\$(exec_prefix)/lib/${withval}";;
    esac
  ]
)
AC_MSG_NOTICE([PAM installation path $PAMDIR])

# CURL
AC_ARG_WITH(
  [curl],
  AS_HELP_STRING([--without-curl], [disable support for curl]),
  [],
  [with_curl=yes]
)

PKG_CHECK_MODULES(
  LIBCURL,
  libcurl,
  [
    AC_SUBST([LIBCURL_CFLAGS])
    AC_SUBST([LIBCURL_LIBS])
  ],
  [
    AC_MSG_ERROR([libcurl not found, please install curl-dev])
  ]
)

AM_CONDITIONAL(COMPILER_IS_CLANG, [test x"$CC" = xclang])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:
  Version:            ${VERSION}
  Host type:          ${host}
  Compiler:           ${CC}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
])

