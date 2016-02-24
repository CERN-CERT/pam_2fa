#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

user_config *get_user_config(pam_handle_t * pamh,
                             const module_config *cfg)
{
    _Bool non_root;
    user_config *user_cfg = calloc(1, sizeof(user_config));

    if(!user_cfg) {
        return NULL;
    }

    if (pam_get_user(pamh, &user_cfg->username, NULL) != PAM_SUCCESS) {
        DBG(("Unable to retrieve username!"));
        goto fail;
    }

    DBG(("username = %s", user_cfg->username));

    non_root = strcmp(user_cfg->username, ROOT_USER);

    if (cfg->ldap_enabled && non_root) {
#ifdef HAVE_LDAP
        //GET 2nd FACTORS FROM LDAP
        if (ldap_search_factors(pamh, cfg, user_cfg->username, user_cfg) < 0) {
            pam_syslog(pamh, LOG_ERR, "LDAP request failed for user '%s'", user_cfg->username);
            goto fail;
        }
#else
	DBG(("LDAP configured, but not compiled (should never happen!)"));
#endif
    } else {
        //NO LDAP QUERY
        struct passwd *user_entry = NULL;
        struct pam_2fa_privs p;

        user_entry = pam_modutil_getpwnam(pamh, user_cfg->username);
        if(!user_entry) {
            pam_syslog(pamh, LOG_ERR, "Can't get passwd entry for '%s'", user_cfg->username);
            goto fail;
        }

#ifdef HAVE_CURL
        if(cfg->gauth_enabled && non_root)
            strncpy(user_cfg->gauth_login, user_cfg->username, GAUTH_LOGIN_LEN + 1);
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
