#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "pam_2fa.h"
#include "curl.h"

int yk_auth_func(pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp);

const auth_mod yk_auth = {
    .do_auth = &yk_auth_func,
    .name = "Yubikey",
    .prompt = "Yubikey: ",
    .otp_len = YK_OTP_LEN,
};

static int valid_otp(module_config * cfg, const char *otp)
{
    unsigned int i = 0;

    for (i = 0; otp[i]; ++i) {
        if (!isalpha(otp[i])) {
            DBG(("INCORRRECT code from user!"))
            return 0;
        }
    }
    if (i != YK_OTP_LEN) {
        DBG(("INCORRRECT code from user!"))
        return 0;
    }

    return 1;
}

/* There is no escape issue as both the username and key can't contain '"' */
static const char * const yk_association_request = "{\"username\": \"%s\", \"yubicode\": \"%s\"}";
static const char * const yk_association_ok = "true";

int yk_auth_func(pam_handle_t * pamh, module_config * cfg, const char* username, const char *otp)
{
    struct pam_curl_state* state;
    struct curl_response* resp;
    char * payload;
    int return_value = PAM_AUTH_ERR;

    DBG(("Yubikey = %s", otp));
    pam_syslog(pamh, LOG_DEBUG, "Yubikey OTP: %s (%zu)", otp, strlen(otp));

    if (!valid_otp(cfg, otp)) {
        return PAM_AUTH_ERR;
    }

    state = pam_curl_init(pamh, cfg);
    if (state == NULL) {
        return 0;
    }
    resp = (struct curl_response*) calloc(1, sizeof(struct curl_response));
    if (resp == NULL) {
        goto clean_state;
    }
    if (asprintf(&payload, yk_association_request, username, otp) < 0) {
        goto clean_resp;
    }

    PAM_CURL_DO_OR_GOTO(state, add_header, clean_payload, "Content-Type: text/json");
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_payload, CURLOPT_FAILONERROR, 1);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_payload, CURLOPT_WRITEFUNCTION, &curl_callback_copy);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_payload, CURLOPT_WRITEDATA, &resp->buffer);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_payload, CURLOPT_URL, cfg->yk_uri);
    PAM_CURL_DO_OR_GOTO(state, set_option, clean_payload, CURLOPT_POSTFIELDS, payload);

    if (pam_curl_perform(state) != CURLE_OK) {
        goto clean_payload;
    }
    if (strcmp(yk_association_ok, resp->buffer) == 0) {
        return_value = PAM_SUCCESS;
    }
clean_payload:
    free(payload);
clean_resp:
    free(resp);
clean_state:
    pam_curl_cleanup(state);
    return return_value;
}
