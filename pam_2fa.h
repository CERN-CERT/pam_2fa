#ifndef HEADER_PAM_2FA_H
#define HEADER_PAM_2FA_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>

// These #defines must be present according to PAM documentation
#define PAM_SM_AUTH

#include <security/pam_appl.h>	//to be correctly init, define it before including pam_modules.h
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#define DEBUG
#include <security/_pam_macros.h>

#ifdef DBG
#undef DBG
#endif
#define DBG(x) if (cfg->debug) { D(x); }


typedef struct {
    int debug;
    unsigned int retry;
    char *capath;
    int ldap_enabled;
    char *ldap_uri;
    char *ldap_basedn;
    char *ldap_attr;
    int gauth_enabled;
    char *gauth_prefix;
    size_t gauth_prefix_len;
    char *gauth_uri_prefix;
    char *gauth_uri_suffix;
    char *smtp_server;
    int yk_enabled;
    char *yk_prefix;
    size_t yk_prefix_len;
    char *yk_uri;
    unsigned int yk_id;
    char *yk_key;
    char *yk_user_file;
    char *domain;
} module_config;


#define GAUTH_LOGIN_LEN 31
#define YK_PUBLICID_LEN 12

typedef struct {
    const char *username;
    _Bool username_allocated;
    char gauth_login[GAUTH_LOGIN_LEN + 1];
    char **yk_publicids;
} user_config;

struct pam_2fa_privs {
    unsigned int is_dropped;
    uid_t old_uid;
    gid_t old_gid;
    gid_t *grplist;
    int nbgrps;
};

typedef int (*auth_func) (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, const char *otp);

typedef struct {
    auth_func do_auth;
    const char * name;
    size_t otp_len;
    const char * prompt;
} auth_mod;

#define AUTHTOK_INCORRECT "\b\n\r\177INCORRECT"

#define LOG_PREFIX "[pam_2fa] "

#define ROOT_USER "root"

#define YK_DEFAULT_USER_FILE ".ssh/trusted_yubikeys"
#define MAX_RETRY 1

#define GAUTH_OTP_LEN 6
#define GAUTH_DEFAULT_ACTION "CheckUser"

#define YK_OTP_LEN 44
#define YK_IDS_DEFAULT_SIZE 8

#define GAUTH_PREFIX "GAuth:"
#define YK_PREFIX    "YubiKey:"

#define ERROR_BINDING_LDAP_SERVER -100
#define ERROR_CONNECTION_LDAP_SERVER -101
#define ERROR_SEARCH_LDAP -102
#define ERROR_NORESULT_LDAP -103
#define ERROR_ALLOCATING_BASE -104

#define OK 666
#define ERROR -1
#define CONFIG_ERROR -2666
#define SEARCH_ERR -3663
#define SEARCH_SUCCESS 6655

int parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg);
void free_config(module_config *cfg);

user_config *get_user_config(pam_handle_t * pamh, const module_config *cfg);
void free_user_config(user_config * user_cfg);

int pam_2fa_drop_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw);
int pam_2fa_regain_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw);

#ifdef HAVE_LDAP
int ldap_search_factors(pam_handle_t *pamh, const module_config * cfg, const char *username, user_config *user_cfg);
#endif

extern const auth_mod gauth_auth;

#ifdef HAVE_YKCLIENT
int yk_load_user_file(pam_handle_t *pamh, const module_config *cfg, struct passwd *user_entry, char ***user_publicids);
int yk_get_publicid(pam_handle_t *pamh, char *buf, size_t *yk_id_pos, size_t *yk_id_len, char ***yk_publicids);
void yk_free_publicids(char **publicids);

extern const auth_mod yk_auth;
#endif

#endif /* HEADER_PAM_2FA_H */
