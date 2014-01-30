#
# Compiling
#
ACLOCAL_AMFLAGS = -I m4
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
        -Wunsafe-loop-optimizations \
        -fPIC

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_2fa.la
pam_2fa_la_SOURCES = pam_2fa_ldap.c pam_2fa_gauth.c pam_2fa_sms.c pam_2fa_yk.c pam_2fa_priv.c pam_2fa.c
pam_2fa_la_CFLAGS = $(LIBCURL_CFLAGS) $(LIBLDAP_CFLAGS) $(LIBYKCLIENT_CFLAGS) $(AM_CFLAGS)
pam_2fa_la_LIBADD = $(LIBCURL_LIBS) $(LIBLDAP_LIBS) $(LIBYKCLIENT_LIBS) $(AM_LDFLAGS) -lpam
pam_2fa_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	find $(DESTDIR)$(libdir) -type f -name \*.la -delete
	find $(DESTDIR)$(libdir) -type f -name \*.a -delete
