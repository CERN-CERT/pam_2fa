#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"
#include "curl.h"

int gauth_auth_func (pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp);

const auth_mod gauth_auth = {
    .do_auth = &gauth_auth_func,
    .name = "Authenticator App",
    .prompt = "OTP: ",
    .otp_len = GAUTH_OTP_LEN,
};

static int valid_otp(pam_handle_t * pamh, module_config * cfg, const char *otp)
{
    unsigned int i = 0;

    for (i = 0; otp[i]; ++i) {
        if (!isdigit(otp[i])) {
            DBG_C(pamh, cfg, "INCORRRECT code from user: non-digit");
            return 0;
        }
    }
    if (i != GAUTH_OTP_LEN) {
        DBG_C(pamh, cfg, "INCORRRECT code from user: wrong length");
        return 0;
    }

    return 1;
}

int gauth_auth_func (pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp)
{
    struct pam_curl_state* state;
    void * ignore_data;
    char * uri;
    int return_value = PAM_AUTH_ERR;

    if (!valid_otp(pamh, cfg, otp)) {
        USER_ERR_C(pamh, cfg, "Invalid OTP provided by user");
        return PAM_AUTH_ERR;
    }

    state = pam_curl_init(pamh, cfg);
    if (state == NULL ) {
        /* Errors already logged in pam_curl_init */
        return PAM_AUTH_ERR;
    }

    /* add_header and set_option already log errors */
    PAM_CURL_DO_OR_GOTO(state, add_header, clean, "Content-Type: text/plain");
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_FAILONERROR, 1);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_WRITEFUNCTION, &curl_callback_ignore);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_WRITEDATA, &ignore_data);

    if (asprintf(&uri, "%s/%s/%s", cfg->gauth_uri_prefix, username, cfg->gauth_uri_suffix) < 0) {
        ERR_C(pamh, cfg, "Gauth: unable to allocate URI");
        goto clean;
    }
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_uri, CURLOPT_URL, uri);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_uri, CURLOPT_POSTFIELDS, otp);

    if (pam_curl_perform(state) == CURLE_OK) {
        return_value = PAM_SUCCESS;
    }
clean_uri:
    free(uri);
clean:
    pam_curl_cleanup(state);
    return return_value;
}
