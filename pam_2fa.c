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
            USER_ERR_C(pamh, cfg, "Unable to get user input (%s)", selected_auth_mod->prompt);
            return PAM_AUTH_ERR;
        }
        if (user_input == NULL) {
            USER_ERR_C(pamh, cfg, "Invalid input received from user (%s)", selected_auth_mod->prompt);
            return PAM_AUTH_ERR;
        }
    }

    retval = selected_auth_mod->do_auth(pamh, cfg, username, user_input);
    free(user_input);
    return retval;
}

static int do_menu_actions(pam_handle_t * pamh, module_config *cfg, const auth_mod **available_mods, int menu_len, const char *username)
{
    int i;
    char *user_input;
    size_t user_input_len;

    if (menu_len > 1) {
        pam_info(pamh, "Login for %s:\n", username);
        for (i = 0; i < menu_len; ++i) {
            pam_info(pamh, "        %d. %s", i+1, available_mods[i]->name);
        }

        if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "\nOption (1-%d): ", menu_len) != PAM_SUCCESS) {
            USER_ERR_C(pamh, cfg, "Unable to get 2nd factors");
            return PAM_AUTH_ERR;
        }
        if (user_input == NULL) {
            USER_ERR_C(pamh, cfg, "Invalid input from user");
            return PAM_AUTH_ERR;
        }

        user_input_len = strlen(user_input);
        for (i = 0; i < menu_len; ++i) {
            if (available_mods[i]->otp_len) {
                if (user_input_len == available_mods[i]->otp_len) {
                    return do_authentication(pamh, cfg, available_mods[i], username, user_input);
                }
            }
        }

        /* No option selected based on OTP len, check if it matches the menu */
        if (user_input_len == 1 && user_input[0] >= '1' && user_input[0] < menu_len + '1') {
            const auth_mod *selected_auth_mod = available_mods[user_input[0] - '1'];
            free(user_input);
            return do_authentication(pamh, cfg, selected_auth_mod, username, NULL);
        } else {
            USER_ERR_C(pamh, cfg, "Invalid menu option from user");
            free(user_input);
            return PAM_AUTH_ERR;
        }
    } else if (menu_len == 1) {
        return do_authentication(pamh, cfg, available_mods[0], username, NULL);
    } else {
        USER_ERR_C(pamh, cfg, "No supported 2nd factor for user '%s'", username);
        return PAM_AUTH_ERR;
    }
}

// CALLED BY PAM_AUTHENTICATE
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh,
                                   int flags,
                                   int argc, const char **argv)
{
    module_config *cfg = NULL;
    char* username;
    int retval;
    const char *authtok;
    int final_return = PAM_AUTH_ERR;

    cfg = parse_config(pamh, argc, argv, flags);
    if (cfg == NULL) {
        /* Errors already logged in parse_config */
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
        /* Errors already logged in get_user */
        goto clean_cfg;
    }

    const auth_mod *available_mods[3] = { NULL, NULL };
    int menu_len = 0;

    if (cfg->gauth_enabled) {
        available_mods[menu_len] = &gauth_auth;
        ++menu_len;
    }
    if (cfg->yk_enabled) {
        available_mods[menu_len] = &yk_auth;
        ++menu_len;
    }

    final_return = do_menu_actions(pamh, cfg, available_mods, menu_len, username);
    free(username);
clean_cfg:
    free_config(cfg);
    return final_return;
}
