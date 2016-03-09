#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

// local function prototypes
void free_and_reset_str(char** str);
int strdup_or_die(char** dst, const char* src);

/// convenient function for freeing a string ans reset the pointer to 0
void
free_and_reset_str(char** str) 
{
    if (*str) {
        free(*str);
        *str = 0;
    }
}

void
free_config(module_config *cfg)
{
    if (cfg) {
        free_and_reset_str(&cfg->capath);
        free_and_reset_str(&cfg->ldap_uri);
        free_and_reset_str(&cfg->ldap_basedn);
        free_and_reset_str(&cfg->ldap_attr);
        free_and_reset_str(&cfg->gauth_prefix);
        free_and_reset_str(&cfg->gauth_ws_uri);
        free_and_reset_str(&cfg->gauth_ws_action);
        free_and_reset_str(&cfg->sms_prefix);
        free_and_reset_str(&cfg->sms_gateway);
        free_and_reset_str(&cfg->sms_subject);
        free_and_reset_str(&cfg->sms_text);
        free_and_reset_str(&cfg->sms_user_file);
        free_and_reset_str(&cfg->yk_prefix);
        free_and_reset_str(&cfg->yk_uri);
        free_and_reset_str(&cfg->yk_key);
        free_and_reset_str(&cfg->yk_user_file);
        free_and_reset_str(&cfg->domain);
        free(cfg);
    }
}

/// calls strdup and returns whether we had a memory error
int strdup_or_die(char** dst, const char* src)
{
  *dst = strdup(src);
  return *dst ? 0 : 1;
}

int
parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg)
{
    module_config *cfg = NULL;
    int mem_error = 0;
    int i;

    cfg = (module_config *) calloc(1, sizeof(module_config));
    if (!cfg) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        return CONFIG_ERROR;
    }

    for (i = 0; i < argc; ++i) {

        if (strcmp(argv[i], "debug") == 0) {
            cfg->debug = 1;

        } else if (strncmp(argv[i], "max_retry=", 10) == 0) {
            sscanf(argv[i], "max_retry=%d", &cfg->retry);
            if (cfg->retry < MAX_RETRY)
                cfg->retry = MAX_RETRY;

        } else if (strncmp(argv[i], "capath=", 7) == 0) {
          mem_error = strdup_or_die(&cfg->capath, argv[i] + 7);

        } else if (strncmp(argv[i], "otp_length=", 11) == 0) {
            sscanf(argv[i], "otp_length=%zu", &cfg->otp_length);
            if (cfg->otp_length < OTP_LENGTH)
                cfg->otp_length = OTP_LENGTH;

#ifdef HAVE_LDAP
        } else if (strncmp(argv[i], "ldap_uri=", 9) == 0) {
            mem_error = strdup_or_die(&cfg->ldap_uri, argv[i] + 9);

        } else if (strncmp(argv[i], "ldap_attr=", 10) == 0) {
            mem_error = strdup_or_die(&cfg->ldap_attr, argv[i] + 10);

        } else if (strncmp(argv[i], "ldap_basedn=", 12) == 0) {
            mem_error = strdup_or_die(&cfg->ldap_basedn, argv[i] + 12);
#endif

#ifdef HAVE_CURL
        } else if (strncmp(argv[i], "gauth_prefix=", 13) == 0) {
            mem_error = strdup_or_die(&cfg->gauth_prefix, argv[i] + 13);

        } else if (strncmp(argv[i], "gauth_ws_uri=", 13) == 0) {
            mem_error = strdup_or_die(&cfg->gauth_ws_uri, argv[i] + 13);

        } else if (strncmp(argv[i], "gauth_ws_action=", 16) == 0) {
            mem_error = strdup_or_die(&cfg->gauth_ws_action, argv[i] + 16);
#endif

        } else if (strncmp(argv[i], "sms_prefix=", 11) == 0) {
            mem_error = strdup_or_die(&cfg->sms_prefix, argv[i] + 11);

        } else if (strncmp(argv[i], "sms_gateway=", 12) == 0) {
            mem_error = strdup_or_die(&cfg->sms_gateway, argv[i] + 12);

        } else if (strncmp(argv[i], "sms_subject=", 12) == 0) {
            mem_error = strdup_or_die(&cfg->sms_subject, argv[i] + 12);

        } else if (strncmp(argv[i], "sms_text=", 9) == 0) {
            mem_error = strdup_or_die(&cfg->sms_text, argv[i] + 9);

        } else if (strncmp(argv[i], "sms_user_file=", 14) == 0) {
            mem_error = strdup_or_die(&cfg->sms_text, argv[i] + 14);

#ifdef HAVE_YKCLIENT
        } else if (strncmp(argv[i], "yk_prefix=", 10) == 0) {
            mem_error = strdup_or_die(&cfg->yk_prefix, argv[i] + 10);

        } else if (strncmp(argv[i], "yk_uri=", 7) == 0) {
            mem_error = strdup_or_die(&cfg->yk_uri, argv[i] + 7);

        } else if (strncmp(argv[i], "yk_id=", 6) == 0) {
            sscanf(argv[i], "yk_id=%d", &cfg->yk_id);

        } else if (strncmp(argv[i], "yk_key=", 7) == 0) {
            mem_error = strdup_or_die(&cfg->yk_key, argv[i] + 7);

        } else if (strncmp(argv[i], "yk_user_file=", 13) == 0) {
            mem_error = strdup_or_die(&cfg->yk_user_file, argv[i] + 13);
#endif

        } else if (strncmp(argv[i], "domain=", 7) == 0) {
            mem_error = strdup_or_die(&cfg->domain, argv[i] + 7);

        } else {
            pam_syslog(pamh, LOG_ERR, "Invalid option: %s", argv[i]);
            return CONFIG_ERROR;
        }
    }

    //DEFAULT VALUES
    if (!cfg->retry)
        cfg->retry = MAX_RETRY;
    if (!cfg->otp_length)
        cfg->otp_length = OTP_LENGTH;
    if (!cfg->sms_subject &&  !mem_error)
        mem_error = strdup_or_die(&cfg->sms_subject, SMS_SUBJECT);
    if (!cfg->sms_text &&  !mem_error)
        mem_error = strdup_or_die(&cfg->sms_text, SMS_TEXT);
    if (!cfg->gauth_ws_action &&  !mem_error)
        mem_error = strdup_or_die(&cfg->gauth_ws_action, GAUTH_DEFAULT_ACTION);
    if (!cfg->gauth_prefix &&  !mem_error)
        mem_error = strdup_or_die(&cfg->gauth_prefix, GAUTH_PREFIX);
    if (!cfg->sms_prefix &&  !mem_error)
        mem_error = strdup_or_die(&cfg->sms_prefix, SMS_PREFIX);
    if (!cfg->sms_user_file &&  !mem_error)
        mem_error = strdup_or_die(&cfg->sms_user_file, SMS_DEFAULT_USER_FILE);
    if (!cfg->yk_prefix &&  !mem_error)
        mem_error = strdup_or_die(&cfg->yk_prefix, YK_PREFIX);
    if (!cfg->yk_user_file &&  !mem_error)
        mem_error = strdup_or_die(&cfg->yk_user_file, YK_DEFAULT_USER_FILE);

    // in case we got a memory error in the previous code, give up immediately
    if (mem_error) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        free_config(cfg);
        return CONFIG_ERROR;
    }

    if (cfg->gauth_prefix)
        cfg->gauth_prefix_len = strlen(cfg->gauth_prefix);
    if (cfg->sms_prefix)
        cfg->sms_prefix_len = strlen(cfg->sms_prefix);
    if (cfg->yk_prefix)
        cfg->yk_prefix_len = strlen(cfg->yk_prefix);

#ifdef HAVE_LDAP
    if (cfg->ldap_uri && cfg->ldap_attr && cfg->ldap_basedn)
        cfg->ldap_enabled = 1;
#endif /* HAVE_LDAP */

    if (cfg->gauth_ws_uri && cfg->gauth_ws_action)
        cfg->gauth_enabled = 1;

    if (cfg->sms_gateway)
        cfg->sms_enabled = 1;

    if (cfg->yk_id)
        cfg->yk_enabled = 1;


    DBG(("debug => %d",           cfg->debug));
    DBG(("retry => %d",           cfg->retry));
    DBG(("otp_length => %d",      cfg->otp_length));
    DBG(("capath => %d",          cfg->capath));
#ifdef HAVE_LDAP
    DBG(("ldap_enabled = %s",     cfg->ldap_enabled));
    DBG(("ldap_uri = %s",         cfg->ldap_uri));
    DBG(("ldap_basedn => '%s'",   cfg->ldap_basedn));
    DBG(("ldap_attr => %s",       cfg->ldap_attr));
#endif /* HAVE_LDAP */
    DBG(("gauth_enabled => %s",   cfg->gauth_enabled));
    DBG(("gauth_prefix => %s",    cfg->gauth_prefix));
    DBG(("gauth_ws_uri => %s",    cfg->gauth_ws_uri));
    DBG(("gauth_ws_action => %s", cfg->gauth_ws_action));
    DBG(("sms_enabled => %s",     cfg->sms_enabled));
    DBG(("sms_prefix => %s",      cfg->sms_prefix));
    DBG(("sms_gateway => %s",     cfg->sms_gateway));
    DBG(("sms_subject => %s",     cfg->sms_subject));
    DBG(("sms_text => %s",        cfg->sms_text));
    DBG(("sms_user_file => %s",   cfg->sms_user_file));
    DBG(("yk_enabled => %s",      cfg->yk_enabled));
    DBG(("yk_prefix => %s",       cfg->yk_prefix));
    DBG(("yk_uri => %s",          cfg->yk_uri));
    DBG(("yk_id => %s",           cfg->yk_id));
    DBG(("yk_key => %s",          cfg->yk_key));
    DBG(("yk_user_file => %s",    cfg->yk_user_file));
    DBG(("domain => %s",          cfg->domain));

    if (!cfg->gauth_enabled && !cfg->sms_enabled && !cfg->yk_enabled) {
        pam_syslog(pamh, LOG_ERR, "No configured 2nd factors");
        free_config(cfg);
        return CONFIG_ERROR;
    }

    *ncfg = cfg;
    return OK;
}
