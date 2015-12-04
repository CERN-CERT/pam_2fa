#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([pam_2fa], [0.1], [Computer.Security@cern.ch])
AC_CONFIG_SRCDIR([pam_2fa.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

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
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_GETGROUPS
AC_FUNC_REALLOC
AC_CHECK_FUNCS([bzero gethostname memmove strchr strdup strrchr strstr])

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

# ldap (no pkg-config found)
AC_ARG_WITH(
  [ldap],
  AS_HELP_STRING([--without-ldap], [disable support for ldap]),
  [],
  [with_ldap=yes]
)

LIBLDAP_LIBS=
LIBLDAP_CFLAGS=
HAVE_LDAP=0
AS_IF(
  [test "x$with_ldap" != xno],
  AC_CHECK_LIB(
    [ldap],
    [ldap_init],
    [
      AC_SUBST([LIBLDAP_LIBS], ["-lldap -llber"])
      AM_CONDITIONAL([USE_LDAP], true)
      HAVE_LDAP=1
      AC_DEFINE([HAVE_LDAP], [1], [Define if you have libldap])
    ],
    [
      AC_MSG_WARN([libldap not found, will not be compiled (--without-ldap to disable ldap support)])
      AM_CONDITIONAL([USE_LDAP], false)
    ],
    []
  ),
  AM_CONDITIONAL([USE_LDAP], false)
)

# CURL
AC_ARG_WITH(
  [curl],
  AS_HELP_STRING([--without-curl], [disable support for curl]),
  [],
  [with_curl=yes]
)

LIBCURL_LIBS=
LIBCURL_CFLAGS=
HAVE_CURL=0
AS_IF(
  [test "x$with_curl" != xno],
  [PKG_CHECK_MODULES(
    LIBCURL,
    libcurl,
    [
      AC_SUBST([LIBCURL_CFLAGS])
      AC_SUBST([LIBCURL_LIBS])
      AM_CONDITIONAL([USE_CURL], true)
      HAVE_CURL=1
      AC_DEFINE([HAVE_CURL], [1], [Define if you have curl])
    ],
    [
      AC_MSG_WARN([libcurl not found, will not be compiled (--without-curl to disable curl support)])
      AM_CONDITIONAL([USE_CURL], false)
    ],
    []
  )],
  AM_CONDITIONAL([USE_CURL], false)
)

# ykclient (no pkg-config found)
AC_ARG_WITH(
  [ykclient],
  AS_HELP_STRING([--without-ykclient], [disable support for ykclient]),
  [],
  [with_ykclient=yes]
)

LIBYKCLIENT_LIBS=
LIBYKCLIENT_CFLAGS=
HAVE_YKCLIENT=0
AS_IF(
  [test "x$with_ykclient" != xno],
  AC_CHECK_LIB(
    [ykclient],
    [ykclient_init],
    [
      AC_SUBST([LIBYKCLIENT_LIBS], ["-lykclient"])
      AM_CONDITIONAL([USE_YKCLIENT], true)
      HAVE_YKCLIENT=1
      AC_DEFINE([HAVE_YKCLIENT], [1], [Define if you have ykclient])
    ],
    [
      AC_MSG_WARN([libykclient not found, will not be compiled (--without-ykclient to disable ykclient support)])
      AM_CONDITIONAL([USE_YKCLIENT], false)
    ],
    []
  ),
  AM_CONDITIONAL([USE_YKCLIENT], false)
)

AM_CONDITIONAL(COMPILER_IS_CLANG, [test x"$CC" = xclang])

AC_CONFIG_FILES([Makefile])
#AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:
  Version:            ${VERSION}
  Host type:          ${host}
  Compiler:           ${CC}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
  Dependencies:       LDAP=${HAVE_LDAP}, CURL=${HAVE_CURL}, YKCLIENT=${HAVE_YKCLIENT}
])

