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
    int retry;
    char *capath;
    size_t otp_length;
    int ldap_enabled;
    char *ldap_uri;
    char *ldap_basedn;
    char *ldap_attr;
    int gauth_enabled;
    char *gauth_prefix;
    size_t gauth_prefix_len;
    char *gauth_ws_uri;
    char *gauth_ws_action;
    int sms_enabled;
    char *sms_prefix;
    size_t sms_prefix_len;
    char *sms_user_file;
    char *sms_gateway;
    char *sms_subject;
    char *sms_text;
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
#define SMS_MOBILE_LEN  15
#define YK_PUBLICID_LEN 12

typedef struct {
    const char *username;
    _Bool username_allocated;
    char gauth_login[GAUTH_LOGIN_LEN + 1];
    char sms_mobile[SMS_MOBILE_LEN + 1];
    char **yk_publicids;
} user_config;

struct pam_2fa_privs {
    unsigned int is_dropped;
    uid_t old_uid;
    gid_t old_gid;
    gid_t *grplist;
    int nbgrps;
};

typedef int (*auth_func) (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp);

#define AUTHTOK_INCORRECT "\b\n\r\177INCORRECT"

#define LOG_PREFIX "[pam_2fa] "

#define ROOT_USER "root"

#define YK_DEFAULT_USER_FILE ".ssh/trusted_yubikeys"
#define SMS_DEFAULT_USER_FILE ".ssh/trusted_sms"

#define OTP_LENGTH 6
#define MAX_RETRY 1

#define GAUTH_DEFAULT_ACTION "CheckUser"

#define YK_OTP_LEN 44
#define YK_IDS_DEFAULT_SIZE 8

#define GAUTH_PREFIX "GAuth:"
#define SMS_PREFIX   "SMS:"
#define YK_PREFIX    "YubiKey:"

#define ERROR_BINDING_LDAP_SERVER -100
#define ERROR_CONNECTION_LDAP_SERVER -101
#define ERROR_SEARCH_LDAP -102
#define ERROR_NORESULT_LDAP -103

#define OK 666
#define ERROR -1
#define CONFIG_ERROR -2666
#define SEARCH_ERR -3663
#define SEARCH_SUCCESS 6655

#define SMS_TEXT_WAIT "Please be patient, you will receive shortly a SMS with your authentication code."
#define SMS_TEXT_INSERT_INPUT "Please put this code here: "
#define SMS_SUBJECT ""
#define SMS_TEXT "Your authentication code is: "

int parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg);
void free_config(module_config *cfg);

user_config *get_user_config(pam_handle_t * pamh, const module_config *cfg);
void free_user_config(user_config * user_cfg);

int pam_2fa_drop_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw);
int pam_2fa_regain_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw);

#ifdef HAVE_LDAP
int ldap_search_factors(pam_handle_t *pamh, const module_config * cfg, const char *username, user_config *user_cfg);
#endif

#ifdef HAVE_CURL
int gauth_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp);
#endif

#ifdef HAVE_YKCLIENT
int yk_load_user_file(pam_handle_t *pamh, const module_config *cfg, struct passwd *user_entry, char ***user_publicids);
int yk_get_publicid(pam_handle_t *pamh, char *buf, size_t *yk_id_pos, size_t *yk_id_len, char ***yk_publicids);
void yk_free_publicids(char **publicids);

int yk_auth_func    (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp);
#endif

void sms_load_user_file(pam_handle_t *pamh, const module_config *cfg, struct passwd *user_entry, user_config *user_cfg);

int sms_auth_func   (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp);

#endif /* HEADER_PAM_2FA_H */
