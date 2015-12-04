#
# Compiling
#
ACLOCAL_AMFLAGS = -I m4

if COMPILER_IS_CLANG
  AM_CFLAGS = -Weverything \
        -Wno-padded \
        -Wno-disabled-macro-expansion \
        -Wno-unused-parameter
else
  AM_CFLAGS = -Wall -Wextra \
        -Wbad-function-cast \
        -Wcast-align \
        -Wcast-qual \
        -Wconversion \
        -Wformat-nonliteral \
        -Wformat-security \
        -Winit-self \
        -Wmissing-declarations \
        -Wmissing-include-dirs \
        -Wmissing-format-attribute \
        -Wmissing-prototypes \
        -Wnested-externs \
        -Wpointer-arith \
        -Wredundant-decls \
        -Wshadow \
        -Wstrict-prototypes \
        -Wwrite-strings \
        -Wundef \
        -Wunused \
        -Wno-unused-parameter \
        -Wno-format-zero-length \
        -Wno-format-y2k \
        -Wunsafe-loop-optimizations
endif
AM_CFLAGS += -fPIC

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_2fa.la pam_ssh_user_auth.la
pam_2fa_la_SOURCES = sms.c priv.c module_conf.c pam_2fa.c user_conf.c
pam_2fa_la_CFLAGS = $(AM_CFLAGS)
pam_2fa_la_LIBADD = $(AM_LDFLAGS) -lpam
pam_2fa_la_LDFLAGS = -module -avoid-version

if USE_LDAP
pam_2fa_la_SOURCES += ldap.c
pam_2fa_la_CFLAGS += $(LIBLDAP_CFLAGS)
pam_2fa_la_LIBADD += $(LIBLDAP_LIBS)
endif

if USE_CURL
pam_2fa_la_SOURCES += gauth.c
pam_2fa_la_CFLAGS += $(LIBCURL_CFLAGS)
pam_2fa_la_LIBADD += $(LIBCURL_LIBS)
endif

if USE_YKCLIENT
pam_2fa_la_SOURCES += yk.c
pam_2fa_la_CFLAGS += $(LIBYKCLIENT_CFLAGS)
pam_2fa_la_LIBADD += $(LIBYKCLIENT_LIBS)
endif

pam_ssh_user_auth_la_SOURCES = pam_ssh_user_auth.c
pam_ssh_user_auth_la_CFLAGS = $(AM_CFLAGS)
pam_ssh_user_auth_la_LIBADD = $(AM_LDFLAGS) -lpam
pam_ssh_user_auth_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	find $(DESTDIR)$(libdir) -type f -name \*.la -delete
	find $(DESTDIR)$(libdir) -type f -name \*.a -delete
