#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

// local function prototypes
static void free_and_reset_str(char** str);
static int strdup_or_die(char** dst, const char* src);
static int raw_parse_option(pam_handle_t *pamh, const char* buf,
                            const char* opt_name_with_eq, char** dst);
static int parse_str_option(pam_handle_t *pamh, const char* buf,
                            const char* opt_name_with_eq, char** dst);
static int parse_uint_option(pam_handle_t *pamh, const char* buf,
                             const char* opt_name_with_eq, unsigned int* dst);

/// convenient function for freeing a string ans reset the pointer to 0
void
free_and_reset_str(char** str)
{
    free(*str);
    *str = NULL;
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
        free_and_reset_str(&cfg->gauth_uri_prefix);
        free_and_reset_str(&cfg->gauth_uri_suffix);
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
    return *dst ? 0 : -1;
}

/**
 * Handles the basic parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found
 * returns -1 if an error occured (duplicate option)
 * returns the position of the start of the value in the buffer otherwise
 */
int raw_parse_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
    size_t opt_len = strlen(opt_name_with_eq);
    if (0 == strncmp(buf, opt_name_with_eq, opt_len)) {
        if (dst && *dst) {
            pam_syslog(pamh, LOG_ERR,
                       "Duplicated option : %s. Only first one is taken into account",
                       opt_name_with_eq);
            return -1;
        } else {
          return (int)opt_len;
        }
    }
    return 0;
}

/**
 * Handles the parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * @arg dst is the destination buffer for the value found if any.
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found in the buffer
 * returns 1 if the option was found in buffer and parsed properly
 * returns -1 in case of error
 */
int parse_str_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
  int value_pos = raw_parse_option(pamh, buf, opt_name_with_eq, dst);
    if (value_pos > 0) {
        if (strdup_or_die(dst, buf+value_pos)) {
            return -1;
        }
        return 1;
    } else if (value_pos == -1) {
      // Don't crash on duplicate, ignore 2nd value
      return 1;
    }
    return value_pos;
}

/**
 * Handles the parsing of a given option with unsigned integer value.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * @arg dst is the destination for the value found if any.
 * returns 0 if the option was not found in the buffer
 * returns 1 if the option was found in buffer and parsed properly
 * returns -1 in case of error
 */
int parse_uint_option(pam_handle_t *pamh, const char* buf,
                      const char* opt_name_with_eq, unsigned int* dst)
{
  int value_pos = raw_parse_option(pamh, buf, opt_name_with_eq, 0);
    if (value_pos > 0) {
        sscanf(buf+value_pos, "%d", dst);
        return 1;
    } else if (value_pos == -1) {
      // Don't crash on duplicate, ignore 2nd value
      return 1;
    }
    return value_pos;
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
        int retval = !strcmp(argv[i], "debug");
        if (retval) cfg->debug = 1;
        if (retval == 0) retval = parse_uint_option(pamh, argv[i], "max_retry=", &cfg->retry);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "capath=", &cfg->capath);
#ifdef HAVE_LDAP
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "ldap_uri=", &cfg->ldap_uri);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "ldap_attr=", &cfg->ldap_attr);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "ldap_basedn=", &cfg->ldap_basedn);
#endif
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "gauth_prefix=", &cfg->gauth_prefix);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "gauth_uri_prefix=", &cfg->gauth_uri_prefix);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "gauth_uri_suffix=", &cfg->gauth_uri_suffix);
#ifdef HAVE_YKCLIENT
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "yk_prefix=", &cfg->yk_prefix);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "yk_uri=", &cfg->yk_uri);
        if (retval == 0) retval = parse_uint_option(pamh, argv[i], "yk_id=", &cfg->yk_id);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "yk_key=", &cfg->yk_key);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "yk_user_file=", &cfg->yk_user_file);
#endif
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "domain=", &cfg->domain);

        if (0 == retval) {
            pam_syslog(pamh, LOG_ERR, "Invalid option: %s", argv[i]);
            free_config(cfg);
            return CONFIG_ERROR;
        } else if (retval < 0) {
            mem_error = retval;
            break;
        }
    }

    //DEFAULT VALUES
    if (!cfg->retry &&  !mem_error)
        cfg->retry = MAX_RETRY;
    if (!cfg->gauth_prefix &&  !mem_error)
        mem_error = strdup_or_die(&cfg->gauth_prefix, GAUTH_PREFIX);
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
    if (cfg->yk_prefix)
        cfg->yk_prefix_len = strlen(cfg->yk_prefix);

#ifdef HAVE_LDAP
    if (cfg->ldap_uri && cfg->ldap_attr && cfg->ldap_basedn)
        cfg->ldap_enabled = 1;
#endif /* HAVE_LDAP */

    if (cfg->gauth_uri_prefix && cfg->gauth_uri_suffix)
        cfg->gauth_enabled = 1;

    if (cfg->yk_id)
        cfg->yk_enabled = 1;


    DBG(("debug => %d",           cfg->debug));
    DBG(("retry => %d",           cfg->retry));
    DBG(("capath => %d",          cfg->capath));
#ifdef HAVE_LDAP
    DBG(("ldap_enabled = %s",     cfg->ldap_enabled));
    DBG(("ldap_uri = %s",         cfg->ldap_uri));
    DBG(("ldap_basedn => '%s'",   cfg->ldap_basedn));
    DBG(("ldap_attr => %s",       cfg->ldap_attr));
#endif /* HAVE_LDAP */
    DBG(("gauth_enabled => %s",   cfg->gauth_enabled));
    DBG(("gauth_prefix => %s",    cfg->gauth_prefix));
    DBG(("gauth_uri_prefix => %s",cfg->gauth_uri_prefix));
    DBG(("gauth_uri_suffix => %s",cfg->gauth_uri_suffix));
    DBG(("yk_enabled => %s",      cfg->yk_enabled));
    DBG(("yk_prefix => %s",       cfg->yk_prefix));
    DBG(("yk_uri => %s",          cfg->yk_uri));
    DBG(("yk_id => %s",           cfg->yk_id));
    DBG(("yk_key => %s",          cfg->yk_key));
    DBG(("yk_user_file => %s",    cfg->yk_user_file));
    DBG(("domain => %s",          cfg->domain));

    if (!cfg->gauth_enabled && !cfg->yk_enabled) {
        pam_syslog(pamh, LOG_ERR, "No configured 2nd factors");
        free_config(cfg);
        return CONFIG_ERROR;
    }

    *ncfg = cfg;
    return OK;
}
