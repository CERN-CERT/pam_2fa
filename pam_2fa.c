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


// CALLED BY PAM_AUTHENTICATE
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh,
                                   __attribute__((unused)) int flags, /* TODO: We should honor PAM_SILENT somehow */
                                   int argc, const char **argv)
{
    module_config *cfg = NULL;
    char* username;
    int retval;
    const char *authtok = NULL;

    cfg = parse_config(pamh, argc, argv);
    if (cfg == NULL) {
        ERR(pamh, "Invalid parameters to pam_2fa module");
        pam_error(pamh, "Sorry, 2FA Pam Module is misconfigured, please contact admins!\n");
        return PAM_AUTH_ERR;
    }

    retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &authtok);
    if (retval != PAM_SUCCESS || (authtok != NULL && !strcmp(authtok, AUTHTOK_INCORRECT))) {
        DBG_C(pamh, cfg, "Previous authentication failed, let's stop here!");
        free_config(cfg);
        return PAM_AUTH_ERR;
    }

    // Get User
    username = get_user(pamh, cfg);
    if (!username) {
        // cleanup
        free_config(cfg);
        return PAM_AUTH_ERR;
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

    retval = PAM_AUTH_ERR;
    do {
        const auth_mod *selected_auth_mod = NULL;
        char *user_input = NULL;
        if (menu_len > 1) {
            size_t user_input_len;
            int i = 1;

            pam_info(pamh, "Login for %s:\n", username);
            for (i = 1; i <= menu_len; ++i) {
                pam_info(pamh, "        %d. %s", i, available_mods[i]->name);
            }

            if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "\nOption (1-%d): ", menu_len) != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_INFO, "Unable to get 2nd factors for user '%s'", username);
                pam_error(pamh, "Unable to get user input");
                retval = PAM_AUTH_ERR;
                break;
            }
            if (user_input == NULL) {
                pam_error(pamh, "Invalid input");
                break;
            }

            user_input_len = strlen(user_input);
            for (i = 1; i <= menu_len; ++i) {
                if (available_mods[i]->otp_len) {
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
            pam_syslog(pamh, LOG_INFO, "No supported 2nd factor for user '%s'", username);
            pam_error(pamh, "No supported 2nd factors for user '%s'", username);
            retval = PAM_AUTH_ERR;
            break;
        }
        if (selected_auth_mod != NULL) {
            if (user_input == NULL) {
                if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_input, "%s", selected_auth_mod->prompt) != PAM_SUCCESS) {
                    pam_syslog(pamh, LOG_INFO, "Unable to get %s", selected_auth_mod->prompt);
                    pam_error(pamh, "Unable to get user input");
                    retval = PAM_AUTH_ERR;
                    break;
                }
                if (user_input == NULL) {
                    pam_error(pamh, "Invalid input");
                    break;
                }
            }
            retval = selected_auth_mod->do_auth(pamh, cfg, username, user_input);
            free(user_input);
        }
    } while (0);

    // final cleanup
    free(username);
    free_config(cfg);
    return retval;
}
