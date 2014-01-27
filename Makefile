#
# Compiling
#
OS:=$(shell uname)
CC=gcc -g
CFLAGS = -Wall -Wextra -Werror \
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
LDFLAGS = -lpam -lldap -lcurl -lykclient

all: pam_2fa.so

%.o: %.c pam_2fa.h

pam_2fa.so: pam_2fa.c pam_2fa_ldap.o pam_2fa_gauth.o pam_2fa_sms.o pam_2fa_yk.o
	$(CC) $(CFLAGS) -DDEBUG_PAM -DPAM_DEBUG -shared $(LDFLAGS) -o $@ $^

install_all: install

install:
	@dst="`find /lib*/security /lib*/*/security -maxdepth 1               \
	            -name pam_unix.so -printf '%H' -quit 2>/dev/null`";       \
	[ -d "$${dst}" ] || dst=/lib/security;                                \
	[ -d "$${dst}" ] || dst=/usr/lib;                                     \
	echo cp pam_2fa.so $${dst} && cp pam_2fa.so $${dst}

clean:
	rm -f pam_2fa.so *.o
