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
        free_and_reset_str(&cfg->gauth_uri_prefix);
        free_and_reset_str(&cfg->gauth_uri_suffix);
        free_and_reset_str(&cfg->yk_uri);
        free_and_reset_str(&cfg->domain);
        free_and_reset_str(&cfg->trusted_file);
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
            ERR(pamh, 0,
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

module_config *
parse_config(pam_handle_t *pamh, int argc, const char **argv, int flags)
{
    module_config *cfg = NULL;
    int mem_error = 0;
    int i;

    cfg = (module_config *) calloc(1, sizeof(module_config));
    if (!cfg) {
        ERR(pamh, flags, "Out of memory, unable to allocate configuration");
        return NULL;
    }
    cfg->flags = flags;

    for (i = 0; i < argc; ++i) {
        int retval = !strcmp(argv[i], "debug");
        if (retval) cfg->debug = 1;
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "capath=", &cfg->capath);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "gauth_uri_prefix=", &cfg->gauth_uri_prefix);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "gauth_uri_suffix=", &cfg->gauth_uri_suffix);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "yk_uri=", &cfg->yk_uri);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "domain=", &cfg->domain);
        if (retval == 0) retval = parse_str_option(pamh, argv[i], "trusted_file=", &cfg->domain);

        if (0 == retval) {
            ERR(pamh, flags, "Invalid configuration option: %s", argv[i]);
            free_config(cfg);
            return NULL;
        } else if (retval < 0) {
            mem_error = retval;
            break;
        }
    }

    //DEFAULT VALUES
    if (!cfg->trusted_file && !mem_error)
        mem_error = strdup_or_die(&cfg->trusted_file, DEFAULT_TRUSTED_FILE);

    // in case we got a memory error in the previous code, give up immediately
    if (mem_error) {
        ERR(pamh, flags, "Out of memory, unable to parse configuration");
        free_config(cfg);
        return NULL;
    }
    if (cfg->gauth_uri_prefix && cfg->gauth_uri_suffix)
        cfg->gauth_enabled = 1;

    if (cfg->yk_uri)
        cfg->yk_enabled = 1;

    if (cfg->debug) {
        DBG(pamh, 1, "debug => %d",           cfg->debug);
        DBG(pamh, 1, "flags => %i",           cfg->flags);
        DBG(pamh, 1, "capath => %s",          cfg->capath);
        DBG(pamh, 1, "gauth_enabled => %i",   cfg->gauth_enabled);
        DBG(pamh, 1, "gauth_uri_prefix => %s",cfg->gauth_uri_prefix);
        DBG(pamh, 1, "gauth_uri_suffix => %s",cfg->gauth_uri_suffix);
        DBG(pamh, 1, "yk_enabled => %i",      cfg->yk_enabled);
        DBG(pamh, 1, "yk_uri => %s",          cfg->yk_uri);
        DBG(pamh, 1, "domain => %s",          cfg->domain);
        DBG(pamh, 1, "trusted_file => %s",    cfg->trusted_file);
    }

    if (!cfg->gauth_enabled && !cfg->yk_enabled) {
        ERR(pamh, flags, "No configured 2nd factors");
        free_config(cfg);
        return NULL;
    }

    return cfg;
}
