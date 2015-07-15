#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <curl/curl.h>

#include "pam_2fa.h"

// Initialize curl when loading the shared library
void __module_load(void)   __attribute__((constructor));
void __module_unload(void) __attribute__((destructor));

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      const char **argv)
{
    return PAM_SUCCESS;
}


// CALLED BY PAM_AUTHENTICATE
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    module_config *cfg = NULL;
    user_config *user_cfg = NULL;
    int retval;
    size_t resp_len = 0;
    char *resp = NULL, *otp = NULL;
    const char *username = NULL;
    const char *authtok = NULL;
    const char *env_value = NULL;
    auth_func selected_auth_func = NULL;
    _Bool non_root = 0, gauth_ok = 0, sms_ok = 0, yk_ok = 0;

    env_value = pam_getenv(pamh, "PAM_2FA");
    if (env_value != NULL) {
        if (strcmp(env_value, "SUCCESS") == 0) {
            pam_syslog(pamh, LOG_INFO, "bypassing 2FA");
            retval = PAM_IGNORE;
        } else {
            retval = PAM_AUTH_ERR;
        }
        goto done;
    }

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);
    if (retval != PAM_SUCCESS || (authtok != NULL && !strcmp(authtok, AUTHTOK_INCORRECT))) {
        DBG(("Previous authentication failed, let's stop here!"));
	retval = PAM_AUTH_ERR;
	goto done;
    }

    retval = parse_config(pamh, argc, argv, &cfg);

    //CHECK PAM CONFIGURATION
    if (retval == CONFIG_ERROR) {
        DBG(("Invalid configuration"));
	pam_syslog(pamh, LOG_ERR, "Invalid parameters to pam_2fa module");
	pam_error(pamh, "Sorry, 2FA Pam Module is misconfigured, please contact admins!\n");

	retval = PAM_AUTH_ERR;
	goto done;
    }
    //GET USERNAME
    retval = pam_get_user(pamh, &username, NULL);

    if (retval != PAM_SUCCESS) {
	DBG(("Unable to retrieve username!"));
	retval = PAM_AUTH_ERR;
	goto done;
    }

    DBG(("username = %s", username));

    user_cfg = (user_config *) calloc(1, sizeof(user_config));
    if(!user_cfg) {
        retval = PAM_AUTH_ERR;
        goto done;
    }

    non_root = strcmp(username, ROOT_USER);

    if (cfg->ldap_enabled && non_root) {
#ifdef HAVE_LDAP
        //GET 2nd FACTORS FROM LDAP
        retval = ldap_search_factors(pamh, cfg, username, user_cfg);
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
            retval = PAM_AUTH_ERR;
            goto done;
        }

#ifdef HAVE_CURL
        if(cfg->gauth_enabled && non_root)
            strncpy(user_cfg->gauth_login, username, GAUTH_LOGIN_LEN + 1);
#endif

#ifdef HAVE_YKCLIENT
        pam_2fa_drop_priv(pamh, &p, user_entry);
        yk_load_user_file(pamh, cfg, user_entry, &user_cfg->yk_publicids);
        pam_2fa_regain_priv(pamh, &p);
#endif

        retval = OK;
    }

    if (retval != OK) {
	pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", username);
	pam_error(pamh, "Unable to get 2nd factors for user '%s'", username);
	retval = PAM_AUTH_ERR;
	goto done;
    }

    auth_func menu_functions[4] = { 0, 0, 0, 0 };
    int menu_len = 0;

    if (cfg->gauth_enabled) {
#ifdef HAVE_CURL
	++menu_len;
	menu_functions[menu_len] = &gauth_auth_func;
        gauth_ok = 1;
#else
	DBG(("GAuth configured, but CURL not compiled (should never happen!)"));
#endif
    }
    if (cfg->sms_enabled) {
	++menu_len;
	menu_functions[menu_len] = &sms_auth_func;
        sms_ok = 1;
    }
    if (cfg->yk_enabled) {
#ifdef HAVE_YKCLIENT
	++menu_len;
	menu_functions[menu_len] = &yk_auth_func;
        yk_ok = 1;
#else
	DBG(("Yubikey configured, but ykclient not compiled (should never happen!)"));
#endif
    }

    if(non_root) {
        //SHOW THE SELECTION MENU
        int i = 1;

        pam_info(pamh, "Login for %s:\n", username);

        if(gauth_ok)
	    pam_info(pamh, "        %d. Google Authenticator", i++);
        if(sms_ok)
	    pam_info(pamh, "        %d. SMS OTP", i++);
        if(yk_ok)
	    pam_info(pamh, "        %d. Yubikey", i);
    
        while (!selected_auth_func) {
            retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "\nOption (1-%d): ", menu_len);

            if (retval != PAM_SUCCESS) {
        	pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", username);
        	pam_error(pamh, "Unable to get user input");
        	retval = PAM_AUTH_ERR;
        	goto done;
            }
    
            resp_len = resp ? strlen(resp) : 0;
            if(yk_ok && resp_len == YK_OTP_LEN) {
                selected_auth_func = &yk_auth_func;
                otp = resp;
            } else if(gauth_ok && resp_len == cfg->otp_length) {
                selected_auth_func = &gauth_auth_func;
                otp = resp;
            } else if(resp_len == 1 && resp[0] >= '1' && resp[0] <= menu_len + '0') {
                selected_auth_func = menu_functions[resp[0] - '0'];
            } else {
                pam_error(pamh, "Wrong value");
            }
    
            if (resp != NULL) {
                if(!otp) free(resp);
                resp = NULL;
            }
        }
    } else if(yk_ok) {
         selected_auth_func = &yk_auth_func;
    } else {
	pam_syslog(pamh, LOG_INFO, "No supported 2nd factor for user '%s'", username);
	pam_error(pamh, "No supported 2nd factors for user '%s'", username);
	retval = PAM_AUTH_ERR;
	goto done;
    }


    //CALL THE CORRESPONDING AUTHENTICATION METHOD
    retval = selected_auth_func(pamh, user_cfg, cfg, otp);

    if (retval == PAM_SUCCESS) {
        if (pam_putenv(pamh, "PAM_2FA=SUCCESS") != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_INFO, "pam_putenv failed'");
        }
    }

done:
    free_config(cfg);
    if(user_cfg) {
        yk_free_publicids(user_cfg->yk_publicids);
        free(user_cfg);
    }
    return retval;
}

// Initialize curl when loading the shared library
void __module_load(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void __module_unload(void)
{
    curl_global_cleanup();
}
