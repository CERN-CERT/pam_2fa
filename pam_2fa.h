#ifndef HEADER_PAM_2FA_H
#define HEADER_PAM_2FA_H

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

// These #defines must be present according to PAM documentation
#define PAM_SM_AUTH

#include <security/pam_appl.h>	//to be correctly init, define it before including pam_modules.h
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "log.h"

typedef struct {
    int debug;
    int flags;
    char *capath;
    int gauth_enabled;
    char *gauth_uri_prefix;
    char *gauth_uri_suffix;
    int yk_enabled;
    char *yk_uri;
    char *domain;
    char *trusted_file;
} module_config;

// Defaults
#define DEFAULT_TRUSTED_FILE ".k5login"

#define GAUTH_LOGIN_LEN 31
#define YK_PUBLICID_LEN 12

struct pam_2fa_privs {
    unsigned int is_dropped;
    uid_t old_uid;
    GETGROUPS_T old_gid;
    GETGROUPS_T *grplist;
    int nbgrps;
};

typedef int (*auth_func) (pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp);

typedef struct {
    auth_func do_auth;
    const char * name;
    size_t otp_len;
    const char * prompt;
} auth_mod;

#define AUTHTOK_INCORRECT "\b\n\r\177INCORRECT"

#define LOG_PREFIX "[pam_2fa] "

#define GAUTH_OTP_LEN 6
#define YK_OTP_LEN 44

module_config * parse_config(pam_handle_t *pamh, int argc, const char **argv, int flags);
void free_config(module_config *cfg);

char * get_user(pam_handle_t * pamh, const module_config *cfg);

int pam_2fa_drop_priv(pam_handle_t *pamh, const module_config * cfg, struct pam_2fa_privs *p, const struct passwd *pw);
int pam_2fa_regain_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw);

extern const auth_mod gauth_auth;
extern const auth_mod yk_auth;

#endif /* HEADER_PAM_2FA_H */
