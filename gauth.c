#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"
#include "curl.h"

int gauth_auth_func (pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp);

const auth_mod gauth_auth = {
    .do_auth = &gauth_auth_func,
    .name = "Google Authenticator",
    .prompt = "OTP: ",
    .otp_len = GAUTH_OTP_LEN,
};

static int valid_otp(module_config * cfg, const char *otp)
{
    unsigned int i = 0;

    for (i = 0; otp[i]; ++i) {
        if (!isdigit(otp[i])) {
            DBG(("INCORRRECT code from user!"))
            return 0;
        }
    }
    if (i != GAUTH_OTP_LEN) {
        DBG(("INCORRRECT code from user!"))
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

    if (!valid_otp(cfg, otp)) {
        return PAM_AUTH_ERR;
    }

    state = pam_curl_init(pamh, cfg);
    if (state == NULL ) {
        return PAM_AUTH_ERR;
    }

    PAM_CURL_DO_OR_GOTO(state, add_header, clean, "Content-Type: text/plain");
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_FAILONERROR, 1);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_WRITEFUNCTION, &curl_callback_ignore);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean, CURLOPT_WRITEDATA, &ignore_data);

    if (asprintf(&uri, "%s/%s/%s", cfg->gauth_uri_prefix, username, cfg->gauth_uri_suffix) < 0) {
        goto clean;
    }
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_uri, CURLOPT_URL, uri);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_uri, CURLOPT_POSTFIELDS, otp);

    CURLcode perform_retval = pam_curl_perform(state);
    if (perform_retval == CURLE_OK) {
        return_value = PAM_SUCCESS;
    } else if (perform_retval == CURLE_HTTP_RETURNED_ERROR) {
        DBG(("Invalid OTP"))
    }
clean_uri:
    free(uri);
clean:
    pam_curl_cleanup(state);
    return return_value;
}
