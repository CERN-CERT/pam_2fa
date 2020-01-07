#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"
#include "curl.h"

int gauth_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, const char *otp);

const auth_mod gauth_auth = {
    .do_auth = &gauth_auth_func,
    .name = "Google Authenticator",
    .prompt = "OTP: ",
    .otp_len = GAUTH_OTP_LEN,
};

/**
 * Process all the data given by curl by simply ignoring it
 */
static size_t ignore_curl_data (char *ptr, size_t size, size_t nmemb, void *userdata)
{
    return size * nmemb;
}

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

static char* build_uri(user_config * user_cfg, module_config * cfg)
{
    int expected_len, final_len;
    size_t buffer_len;
    char * uri;

    expected_len = snprintf(NULL, 0, "%s/%s/%s", cfg->gauth_uri_prefix, user_cfg->username, cfg->gauth_uri_suffix);
    if (expected_len <= 0)
        return NULL;
    buffer_len = (size_t) expected_len + 1; /* snprintf doesn't count the null byte on its return */
    uri = (char*) calloc(1, buffer_len);
    if (uri == NULL)
        return uri;
    final_len = snprintf(uri, buffer_len, "%s/%s/%s", cfg->gauth_uri_prefix, user_cfg->username, cfg->gauth_uri_suffix);
    if (final_len != expected_len) {
        free(uri);
        return NULL;
    }
    return uri;
}

int gauth_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, const char *otp)
{
    struct pam_curl_state* state;
    void * ignore_data;
    char * uri;

    if (!valid_otp(cfg, otp)) {
        return PAM_AUTH_ERR;
    }

    state = pam_curl_init(pamh, cfg);
    if (state == NULL ) {
        return PAM_AUTH_ERR;
    }

    PAM_CURL_DO_OR_RET(state, add_header, PAM_AUTH_ERR, "Content-Type: text/plain");

    PAM_CURL_DO_OR_RET(state, set_option, PAM_AUTH_ERR, CURLOPT_FAILONERROR, 1);
    PAM_CURL_DO_OR_RET(state, set_option, PAM_AUTH_ERR, CURLOPT_WRITEFUNCTION, &ignore_curl_data);
    PAM_CURL_DO_OR_RET(state, set_option, PAM_AUTH_ERR, CURLOPT_WRITEDATA, &ignore_data);

    uri = build_uri(user_cfg, cfg);
    if (uri == NULL) {
        pam_curl_cleanup(state);
        return PAM_AUTH_ERR;
    }
    PAM_CURL_DO_OR_RET(state, set_option, PAM_AUTH_ERR, CURLOPT_URL, uri);
    free(uri);
    PAM_CURL_DO_OR_RET(state, set_option, PAM_AUTH_ERR, CURLOPT_POSTFIELDS, otp);

    CURLcode perform_retval = pam_curl_perform(state);
    pam_curl_cleanup(state);
    if (perform_retval == CURLE_OK) {
        return PAM_SUCCESS;
    }
    if (perform_retval == CURLE_HTTP_RETURNED_ERROR) {
        DBG(("Invalid OTP"))
    }
    return PAM_AUTH_ERR;
}
