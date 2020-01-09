#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"

PAM_EXTERN int pam_sm_setcred(__attribute__((unused)) pam_handle_t * pamh,
                              __attribute__((unused)) int flags,
                              __attribute__((unused)) int argc,
                              __attribute__((unused)) const char **argv)
{
    return PAM_SUCCESS;
}

static int do_authentication(pam_handle_t * pamh, module_config *cfg, const auth_mod *selected_auth_mod, const char *username, char *user_input)
{
    int retval;

    if (user_input == NULL) {
        if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "%s", selected_auth_mod->prompt) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_INFO, "Unable to get %s", selected_auth_mod->prompt);
            pam_error(pamh, "Unable to get user input");
            return PAM_AUTH_ERR;
        }
        if (user_input == NULL) {
            pam_error(pamh, "Invalid input");
            return PAM_AUTH_ERR;
        }
    }

    retval = selected_auth_mod->do_auth(pamh, cfg, username, user_input);
    free(user_input);
    return retval;
}

static int do_menu_actions(pam_handle_t * pamh, module_config *cfg, const auth_mod **available_mods, int menu_len, const char *username)
{
    char *user_input;
    size_t user_input_len;

    if (menu_len > 1) {
        pam_info(pamh, "Login for %s:\n", username);
        for (int i = 1; i <= menu_len; ++i) {
            pam_info(pamh, "        %d. %s", i, available_mods[i]->name);
        }

        if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "\nOption (1-%d): ", menu_len) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", username);
            pam_error(pamh, "Unable to get user input");
            return PAM_AUTH_ERR;
        }
        if (user_input == NULL) {
            pam_error(pamh, "Invalid input");
            return PAM_AUTH_ERR;
        }

        user_input_len = strlen(user_input);
        for (int i = 1; i <= menu_len; ++i) {
            if (available_mods[i]->otp_len) {
                if (user_input_len == available_mods[i]->otp_len) {
                    return do_authentication(pamh, cfg, available_mods[i], username, user_input);
                }
            }
        }

        /* No option selected based on OTP len, check if it matches the menu */
        if (user_input_len == 1 && user_input[0] >= '1' && user_input[0] <= menu_len + '0') {
            const auth_mod *selected_auth_mod = available_mods[user_input[0] - '0'];
            free(user_input);
            return do_authentication(pamh, cfg, selected_auth_mod, username, NULL);
        } else {
            pam_error(pamh, "Invalid input");
            free(user_input);
            return PAM_AUTH_ERR;
        }
    } else if (menu_len == 1) {
        return do_authentication(pamh, cfg, available_mods[1], username, NULL);
    } else {
        pam_syslog(pamh, LOG_INFO, "No supported 2nd factor for user '%s'", username);
        pam_error(pamh, "No supported 2nd factors for user '%s'", username);
        return PAM_AUTH_ERR;
    }
}

// CALLED BY PAM_AUTHENTICATE
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh,
                                   __attribute__((unused)) int flags, /* TODO: We should honor PAM_SILENT somehow */
                                   int argc, const char **argv)
{
    module_config *cfg = NULL;
    char* username;
    int retval;
    const char *authtok = NULL;
    int final_return = PAM_AUTH_ERR;

    cfg = parse_config(pamh, argc, argv);
    if (cfg == NULL) {
        ERR(pamh, "Invalid parameters to pam_2fa module");
        pam_error(pamh, "Sorry, 2FA Pam Module is misconfigured, please contact admins!\n");
        return PAM_AUTH_ERR;
    }

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);
    if (retval != PAM_SUCCESS || (authtok != NULL && !strcmp(authtok, AUTHTOK_INCORRECT))) {
        DBG_C(pamh, cfg, "Previous authentication failed, let's stop here!");
        goto clean_cfg;
    }

    // Get User
    username = get_user(pamh, cfg);
    if (!username) {
        goto clean_cfg;
    }

    const auth_mod *available_mods[3] = { NULL, NULL, NULL };
    int menu_len = 0;

    if (cfg->gauth_enabled) {
        ++menu_len;
        available_mods[menu_len] = &gauth_auth;
    }
    if (cfg->yk_enabled) {
        ++menu_len;
        available_mods[menu_len] = &yk_auth;
    }

    final_return = do_menu_actions(pamh, cfg, available_mods, menu_len, username);
    free(username);
clean_cfg:
    free_config(cfg);
    return final_return;
}
