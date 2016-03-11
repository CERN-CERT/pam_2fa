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
    unsigned int trial;
    const char *authtok = NULL;

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);
    if (retval != PAM_SUCCESS || (authtok != NULL && !strcmp(authtok, AUTHTOK_INCORRECT))) {
        D(("Previous authentication failed, let's stop here!"));
	return PAM_AUTH_ERR;
    }

    retval = parse_config(pamh, argc, argv, &cfg);

    //CHECK PAM CONFIGURATION
    if (retval == CONFIG_ERROR) {
        D(("Invalid configuration"));
	pam_syslog(pamh, LOG_ERR, "Invalid parameters to pam_2fa module");
	pam_error(pamh, "Sorry, 2FA Pam Module is misconfigured, please contact admins!\n");
        return PAM_AUTH_ERR;
    }

    // Get User configuration
    user_cfg = get_user_config(pamh, cfg);
    if(!user_cfg) {
	pam_syslog(pamh, LOG_INFO, "Unable to get user configuration");
        // cleanup
        free_config(cfg);
	return PAM_AUTH_ERR;
    }

    const auth_mod *available_mods[4] = { NULL, NULL, NULL, NULL };
    int menu_len = 0;

    if (cfg->gauth_enabled && user_cfg->gauth_login[0] != '\0') {
#ifdef HAVE_CURL
	++menu_len;
	available_mods[menu_len] = &gauth_auth;
#else
	DBG(("GAuth configured, but CURL not compiled (should never happen!)"));
#endif
    }
    if (cfg->sms_enabled && user_cfg->sms_mobile[0] != '\0') {
	++menu_len;
	available_mods[menu_len] = &sms_auth;
    }
    if (cfg->yk_enabled && user_cfg->yk_publicids) {
#ifdef HAVE_YKCLIENT
	++menu_len;
	available_mods[menu_len] = &yk_auth;
#else
	DBG(("Yubikey configured, but ykclient not compiled (should never happen!)"));
#endif
    }

    retval = PAM_AUTH_ERR;
    for (trial = 0; trial < cfg->retry && retval != PAM_SUCCESS; ++trial) {
        const auth_mod *selected_auth_mod = NULL;
        char *user_input = NULL;
        if (menu_len > 1) {
            size_t user_input_len;
            int i = 1;

            pam_info(pamh, "Login for %s:\n", user_cfg->username);
            for (i = 1; i <= menu_len; ++i) {
                pam_info(pamh, "        %d. %s", i, available_mods[i]->name);
            }

            if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "\nOption (1-%d): ", menu_len) != PAM_SUCCESS) {
        	pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", user_cfg->username);
        	pam_error(pamh, "Unable to get user input");
        	retval = PAM_AUTH_ERR;
		break;
            }

            user_input_len = user_input ? strlen(user_input) : 0;
            for (i = 1; i <= menu_len; ++i) {
                if (available_mods[i]->preotp && available_mods[i]->otp_len) {
                    if (user_input_len == available_mods[i]->otp_len) {
                        selected_auth_mod = available_mods[i];
                        break;
                    }
                }
            }
            if (selected_auth_mod == NULL) {
                if (user_input_len == 1 && user_input[0] >= '1' && user_input[0] <= menu_len + '0') {
                    selected_auth_mod = available_mods[user_input[0] - '0'];
                    free(user_input);
                    user_input = NULL;
                } else {
                    pam_error(pamh, "Invalid input");
                    free(user_input);
                    user_input = NULL;
                }
            }
        } else if (menu_len == 1) {
            selected_auth_mod = available_mods[1];
        } else {
	    pam_syslog(pamh, LOG_INFO, "No supported 2nd factor for user '%s'", user_cfg->username);
	    pam_error(pamh, "No supported 2nd factors for user '%s'", user_cfg->username);
	    retval = PAM_AUTH_ERR;
            break;
        }
        if (selected_auth_mod != NULL) {
            // If not NULL, user_input has to be freed by the auth function
            retval = selected_auth_mod->do_auth(pamh, user_cfg, cfg, user_input);
        }
    }

    // final cleanup
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
