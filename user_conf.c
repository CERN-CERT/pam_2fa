#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

user_config *get_user_config(pam_handle_t * pamh,
                             const module_config *cfg,
                             const char * username)
{
    _Bool non_root;
    user_config *user_cfg = calloc(1, sizeof(user_config));

    if(!user_cfg) {
        return NULL;
    }

    non_root = strcmp(username, ROOT_USER);

    if (cfg->ldap_enabled && non_root) {
#ifdef HAVE_LDAP
        //GET 2nd FACTORS FROM LDAP
        if (ldap_search_factors(pamh, cfg, username, user_cfg) < 0)
            goto fail;
#else
	DBG(("LDAP configured, but not compiled (should never happen!)"));
#endif
    } else {
        //NO LDAP QUERY
        struct passwd *user_entry = NULL;
        struct pam_2fa_privs p;

        user_entry = pam_modutil_getpwnam(pamh, username);
        if(!user_entry) {
            pam_syslog(pamh, LOG_ERR, "Can't get passwd entry for '%s'", username);
            goto fail;
        }

#ifdef HAVE_CURL
        if(cfg->gauth_enabled && non_root)
            strncpy(user_cfg->gauth_login, username, GAUTH_LOGIN_LEN + 1);
#endif

        pam_2fa_drop_priv(pamh, &p, user_entry);
#ifdef HAVE_YKCLIENT
        yk_load_user_file(pamh, cfg, user_entry, &user_cfg->yk_publicids);
#endif
        sms_load_user_file(pamh, cfg, user_entry, user_cfg);
        pam_2fa_regain_priv(pamh, &p);
    }

    return user_cfg;
fail:
    free(user_cfg);
    return NULL;
}

void free_user_config(user_config * user_cfg)
{
    if(user_cfg) {
#ifdef HAVE_YKCLIENT
        yk_free_publicids(user_cfg->yk_publicids);
#endif
        free(user_cfg);
    }
}
