#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <curl/curl.h>

#include "pam_2fa.h"

// Initialize curl when loading the shared library
void __module_load(void)   __attribute__((constructor));
void __module_unload(void) __attribute__((destructor));

static int parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg);

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

    non_root = strcmp(username, ROOT_USER);

    if (cfg->ldap_enabled && non_root) {
#ifdef HAVE_LDAP
        //GET 2nd FACTORS FROM LDAP
        retval = ldap_search_factors(pamh, cfg, username, &user_cfg);
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

        user_cfg = (user_config *) calloc(1, sizeof(user_config));
        if(!user_cfg) {
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

    if (cfg->gauth_enabled && user_cfg->gauth_login[0]) {
#ifdef HAVE_CURL
	++menu_len;
	menu_functions[menu_len] = &gauth_auth_func;
        gauth_ok = 1;
#else
	DBG(("GAuth configured, but CURL not compiled (should never happen!)"));
#endif
    }
    if (cfg->sms_enabled && user_cfg->sms_mobile[0]) {
	++menu_len;
	menu_functions[menu_len] = &sms_auth_func;
        sms_ok = 1;
    }
    if (cfg->yk_enabled && user_cfg->yk_publicids) {
#ifdef HAVE_YKCLIENT
	++menu_len;
	menu_functions[menu_len] = &yk_auth_func;
        yk_ok = 1;
#else
	DBG(("Yubikey configured, but ykclient not compiled (should never happen!)"));
#endif
    }

    if(menu_len > 1) {
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
    } else if(menu_len == 1) {
         selected_auth_func = menu_functions[1];
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

    if(cfg) free_config(cfg);
    if(user_cfg) free_user_config(user_cfg);
    return retval;
}


static int parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg)
{
    module_config *cfg = NULL;
    int i;

    cfg = (module_config *) calloc(1, sizeof(module_config));
    if(!cfg) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        return CONFIG_ERROR;
    }

    for (i = 0; i < argc; ++i) {

	if (strcmp(argv[i], "debug") == 0)
	    cfg->debug = 1;

	else if (strncmp(argv[i], "max_retry=", 10) == 0) {
	    sscanf(argv[i], "max_retry=%d", &cfg->retry);
	    if (cfg->retry < MAX_RETRY)
		cfg->retry = MAX_RETRY;
	}

	else if (strncmp(argv[i], "capath=", 7) == 0)
	    cfg->capath = strdup(argv[i] + 7);

	else if (strncmp(argv[i], "otp_length=", 11) == 0) {
	    sscanf(argv[i], "otp_length=%zu", &cfg->otp_length);
	    if (cfg->otp_length < OTP_LENGTH)
		cfg->otp_length = OTP_LENGTH;
	}

#ifdef HAVE_LDAP
	else if (strncmp(argv[i], "ldap_uri=", 9) == 0)
	    cfg->ldap_uri = strdup(argv[i] + 9);

	else if (strncmp(argv[i], "ldap_attr=", 10) == 0)
	    cfg->ldap_attr = strdup(argv[i] + 10);

	else if (strncmp(argv[i], "ldap_basedn=", 12) == 0)
	    cfg->ldap_basedn = strdup(argv[i] + 12);
#endif

#ifdef HAVE_CURL
	else if (strncmp(argv[i], "gauth_prefix=", 13) == 0)
	    cfg->gauth_prefix = strdup(argv[i] + 13);

	else if (strncmp(argv[i], "gauth_ws_uri=", 13) == 0)
	    cfg->gauth_ws_uri = strdup(argv[i] + 13);

	else if (strncmp(argv[i], "gauth_ws_action=", 16) == 0)
	    cfg->gauth_ws_action = strdup(argv[i] + 16);
#endif

	else if (strncmp(argv[i], "sms_prefix=", 11) == 0)
	    cfg->sms_prefix = strdup(argv[i] + 11);

	else if (strncmp(argv[i], "sms_gateway=", 12) == 0)
	    cfg->sms_gateway = strdup(argv[i] + 12);

	else if (strncmp(argv[i], "sms_subject=", 12) == 0)
	    cfg->sms_subject = strdup(argv[i] + 12);

	else if (strncmp(argv[i], "sms_text=", 9) == 0)
	    cfg->sms_text = strdup(argv[i] + 9);

#ifdef HAVE_YKCLIENT
	else if (strncmp(argv[i], "yk_prefix=", 10) == 0)
	    cfg->yk_prefix = strdup(argv[i] + 10);

	else if (strncmp(argv[i], "yk_uri=", 7) == 0)
	    cfg->yk_uri = strdup(argv[i] + 7);

	else if (strncmp(argv[i], "yk_id=", 6) == 0)
	    sscanf(argv[i], "yk_id=%d", &cfg->yk_id);

	else if (strncmp(argv[i], "yk_key=", 7) == 0)
	    cfg->yk_key = strdup(argv[i] + 7);

	else if (strncmp(argv[i], "yk_user_file=", 13) == 0)
	    cfg->yk_user_file = strdup(argv[i] + 13);
#endif

        else {
            pam_syslog(pamh, LOG_ERR, "Invalid option: %s", argv[i]);
            return CONFIG_ERROR;
        }
    }

    //DEFAULT VALUES
    if(!cfg->retry)           cfg->retry           = MAX_RETRY;
    if(!cfg->otp_length)      cfg->otp_length      = OTP_LENGTH;
    if(!cfg->sms_subject)     cfg->sms_subject     = strdup(SMS_SUBJECT);
    if(!cfg->sms_text)        cfg->sms_text        = strdup(SMS_TEXT);
    if(!cfg->gauth_ws_action) cfg->gauth_ws_action = strdup(GAUTH_DEFAULT_ACTION);
    if(!cfg->gauth_prefix)    cfg->gauth_prefix    = strdup(GAUTH_PREFIX);
    if(!cfg->sms_prefix)      cfg->sms_prefix      = strdup(SMS_PREFIX);
    if(!cfg->yk_prefix)       cfg->yk_prefix       = strdup(YK_PREFIX);
    if(!cfg->yk_user_file)    cfg->yk_user_file    = strdup(YK_DEFAULT_USER_FILE);

    if(cfg->gauth_prefix)  cfg->gauth_prefix_len = strlen(cfg->gauth_prefix);
    if(cfg->sms_prefix)    cfg->sms_prefix_len   = strlen(cfg->sms_prefix);
    if(cfg->yk_prefix)     cfg->yk_prefix_len    = strlen(cfg->yk_prefix);

    if (cfg->ldap_uri && cfg->ldap_attr && cfg->ldap_basedn)
        cfg->ldap_enabled = 1;

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
    DBG(("ldap_enabled = %s",     cfg->ldap_enabled));
    DBG(("ldap_uri = %s",         cfg->ldap_uri));
    DBG(("ldap_basedn => '%s'",   cfg->ldap_basedn));
    DBG(("ldap_attr => %s",       cfg->ldap_attr));
    DBG(("gauth_enabled => %s",   cfg->gauth_enabled));
    DBG(("gauth_prefix => %s",    cfg->gauth_prefix));
    DBG(("gauth_ws_uri => %s",    cfg->gauth_ws_uri));
    DBG(("gauth_ws_action => %s", cfg->gauth_ws_action));
    DBG(("sms_enabled => %s",     cfg->sms_enabled));
    DBG(("sms_prefix => %s",      cfg->sms_prefix));
    DBG(("sms_gateway => %s",     cfg->sms_gateway));
    DBG(("sms_subject => %s",     cfg->sms_subject));
    DBG(("sms_text => %s",        cfg->sms_text));
    DBG(("yk_enabled => %s",      cfg->yk_enabled));
    DBG(("yk_prefix => %s",       cfg->yk_prefix));
    DBG(("yk_uri => %s",          cfg->yk_uri));
    DBG(("yk_id => %s",           cfg->yk_id));
    DBG(("yk_key => %s",          cfg->yk_key));
    DBG(("yk_user_file => %s",    cfg->yk_user_file));

    if(!cfg->gauth_enabled && !cfg->sms_enabled && !cfg->yk_enabled) {
        pam_syslog(pamh, LOG_ERR, "No configured 2nd factors");
        return CONFIG_ERROR;
    }

    *ncfg = cfg;
    return OK;
}

void free_config(module_config *cfg)
{
    if(cfg) {
        if(cfg->capath)          free(cfg->capath);
        if(cfg->ldap_uri)        free(cfg->ldap_uri);
        if(cfg->ldap_basedn)     free(cfg->ldap_basedn);
        if(cfg->ldap_attr)       free(cfg->ldap_attr);
        if(cfg->gauth_prefix)    free(cfg->gauth_prefix);
        if(cfg->gauth_ws_uri)    free(cfg->gauth_ws_uri);
        if(cfg->gauth_ws_action) free(cfg->gauth_ws_action);
        if(cfg->sms_prefix)      free(cfg->sms_prefix);
        if(cfg->sms_gateway)     free(cfg->sms_gateway);
        if(cfg->sms_subject)     free(cfg->sms_subject);
        if(cfg->sms_text)        free(cfg->sms_text);
        if(cfg->yk_prefix)       free(cfg->yk_prefix);
        if(cfg->yk_uri)          free(cfg->yk_uri);
        if(cfg->yk_key)          free(cfg->yk_key);
        if(cfg->yk_user_file)    free(cfg->yk_user_file);
        free(cfg);
    }
}

void free_user_config(user_config *user_cfg)
{
    if(user_cfg) {
        yk_free_publicids(user_cfg->yk_publicids);
        free(user_cfg);
    }
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
