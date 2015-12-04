#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

#ifdef HAVE_CURL
#include <curl/curl.h>

// Initialize curl when loading the shared library
void __module_load(void)   __attribute__((constructor));
void __module_unload(void) __attribute__((destructor));
#endif

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
    auth_func selected_auth_func = NULL;
    _Bool gauth_ok = 0, sms_ok = 0, yk_ok = 0;

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

    user_cfg = get_user_config(pamh, cfg, username);
    if(!user_cfg) {
	pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", username);
	pam_error(pamh, "Unable to get 2nd factors for user '%s'", username);
	retval = PAM_AUTH_ERR;
	goto done;
    }

    auth_func menu_functions[4] = { 0, 0, 0, 0 };
    int menu_len = 0;

    if (cfg->gauth_enabled && user_cfg->gauth_login[0] != '\0') {
#ifdef HAVE_CURL
	++menu_len;
	menu_functions[menu_len] = &gauth_auth_func;
        gauth_ok = 1;
#else
	DBG(("GAuth configured, but CURL not compiled (should never happen!)"));
#endif
    }
    if (cfg->sms_enabled && user_cfg->sms_mobile[0] != '\0') {
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

    if (menu_len > 1) {
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
#ifdef HAVE_YKCLIENT
            if(yk_ok && resp_len == YK_OTP_LEN) {
                selected_auth_func = &yk_auth_func;
                otp = resp;
            } else
#endif
#ifdef HAVE_CURL
            if(gauth_ok && resp_len == cfg->otp_length) {
                selected_auth_func = &gauth_auth_func;
                otp = resp;
            } else
#endif
            if(resp_len == 1 && resp[0] >= '1' && resp[0] <= menu_len + '0') {
                selected_auth_func = menu_functions[resp[0] - '0'];
            } else {
                pam_error(pamh, "Wrong value");
            }
    
            if (resp != NULL) {
                if(!otp) free(resp);
                resp = NULL;
            }
        }
    } else if (menu_len == 1) {
         selected_auth_func = menu_functions[1];
    } else {
	pam_syslog(pamh, LOG_INFO, "No supported 2nd factor for user '%s'", username);
	pam_error(pamh, "No supported 2nd factors for user '%s'", username);
	retval = PAM_AUTH_ERR;
	goto done;
    }


    //CALL THE CORRESPONDING AUTHENTICATION METHOD
    retval = selected_auth_func(pamh, user_cfg, cfg, otp);

done:
    free_user_config(user_cfg);
    free_config(cfg);
    return retval;
}

#ifdef HAVE_CURL
// Initialize curl when loading the shared library
void __module_load(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void __module_unload(void)
{
    curl_global_cleanup();
}
#endif
