#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <curl/curl.h>

#include "pam_2fa.h"

#define SOAP_REQUEST_TEMPL "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:ns0=\"http://cern.ch/GoogleAuthenticator/\" xmlns:ns1=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><ns1:Body><ns0:CheckUser><ns0:login>%s</ns0:login><ns0:pincode>%s</ns0:pincode></ns0:CheckUser></ns1:Body></SOAP-ENV:Envelope>"

#define HTTP_BUF_LEN 2048

struct response_curl {
    char buffer[HTTP_BUF_LEN];
    size_t size;
};


static size_t writefunc_curl (char *ptr, size_t size, size_t nmemb, void *userdata);
static int cleanup (char* otp, CURL *curlh, struct curl_slist *header_list);
static int check_curl_ret(int retval, char* curl_error, pam_handle_t * pamh, module_config * cfg);

/**
 * cleans up memory allocated for the 3 parameters
 * returns PAM_AUTH_ERR
 */
int cleanup (char* otp, CURL *curlh, struct curl_slist *header_list) 
{
  if (otp) free(otp);
  if (curlh) curl_easy_cleanup(curlh);
  if (header_list) curl_slist_free_all(header_list);
  return PAM_AUTH_ERR;
}

/**
 * check the value of retval.
 * In case of failure, prints an error message.
 * returns 1 if there was a failure, 0 otherwise
 */
int check_curl_ret(int retval, char* curl_error, pam_handle_t * pamh, module_config * cfg)
{
    if (retval != CURLE_OK) {
        DBG(("Unable to set CURL options"));
        pam_syslog(pamh, LOG_ERR, "Unable to set CURL options: %s", curl_error);
        return 1;
    }
    return 0;
}

int gauth_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp)
{
    CURL *curlh = NULL;
    char *p = NULL, *result = NULL;
    char soap_action[1024], soap_result_tag[1024], soap_result_ok[1024];
    char http_request[HTTP_BUF_LEN] = { 0 }, curl_error[CURL_ERROR_SIZE] = { 0 };
    struct response_curl http_response = { .size = 0 };
    int retval = 0;
    unsigned int trial = 0;
    struct curl_slist *header_list = NULL;

    p = strrchr(cfg->gauth_ws_action, '/');
    if (!p || !*++p) {
        DBG(("Invalid WS action"));
        pam_syslog(pamh, LOG_ERR, "Invalid WS action: %s", cfg->gauth_ws_action);
        return PAM_AUTH_ERR;
    }
    snprintf(soap_result_tag, 1024, "<%sResult>", p);
    snprintf(soap_result_ok, 1024, "<%sResult>true</%sResult>", p, p);
    snprintf(soap_action, 1024, "SOAPAction: \"%s\"", cfg->gauth_ws_action);

    //CURL INITIALIZATION
    curlh = curl_easy_init();
    header_list = curl_slist_append(header_list, "Content-Type: text/xml; charset=utf-8");
    header_list = curl_slist_append(header_list, soap_action);

    retval = curl_easy_setopt(curlh, CURLOPT_FAILONERROR, 1);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    retval = curl_easy_setopt(curlh, CURLOPT_ERRORBUFFER, curl_error);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    if (cfg->capath) {
        retval = curl_easy_setopt(curlh, CURLOPT_CAPATH, cfg->capath);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);
    }

    retval = curl_easy_setopt(curlh, CURLOPT_HTTPHEADER, header_list);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    retval = curl_easy_setopt(curlh, CURLOPT_URL, cfg->gauth_ws_uri);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    retval = curl_easy_setopt(curlh, CURLOPT_WRITEFUNCTION, &writefunc_curl);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    retval = curl_easy_setopt(curlh, CURLOPT_WRITEDATA, &http_response);
    if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(otp, curlh, header_list);

    if (!user_cfg->gauth_login[0]) {
        strncpy(user_cfg->gauth_login, "INVALID&&USER&&NAME", GAUTH_LOGIN_LEN);
    }

    //GET USER INPUT
    retval = PAM_AUTH_ERR;
    for (trial = 0; trial < cfg->retry; ++trial) {
        if(!otp)
            pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &otp, "OTP: ");

        if (otp) {
            DBG(("OTP = %s", otp));

            // VERIFY IF VALID INPUT !
            int isValid = 1;
            unsigned int i = 0;
            for (i = 0; isValid && otp[i]; ++i) {
                if (!isdigit(otp[i])) {
                    isValid = 0;
                    break;
                }
            }
            if (!isValid || otp[i]) {
                DBG(("INCORRRECT code from user!"));
                free(otp);
                otp = NULL;
                continue;
            }

            // build and perform HTTP Request
            snprintf(http_request, HTTP_BUF_LEN, SOAP_REQUEST_TEMPL, user_cfg->gauth_login, otp);
            memset(otp, 0, i);
            free(otp);
            otp = NULL;

            int setopt_retval = curl_easy_setopt(curlh, CURLOPT_POSTFIELDS, http_request);
            if (setopt_retval != CURLE_OK) {
                DBG(("Unable to set CURL POST request"));
                pam_syslog(pamh, LOG_ERR, "Unable to set CURL POST request: %s", curl_error);
                break;
            }

            int perform_retval = curl_easy_perform(curlh);
            if (perform_retval) {
                DBG(("curl return value (%d): %s", perform_retval, curl_error));
                break;
            }

            // PARSE THE RESPONSE
            http_response.buffer[http_response.size] = 0;
            http_response.size = 0;
            result = strstr(http_response.buffer, soap_result_tag);
            if (result == NULL) {
                DBG(("Invalid SOAP response: %s", http_response.buffer));
                pam_syslog(pamh, LOG_ERR, "Invalid SOAP response: %s", http_response.buffer);
                break;
            }

            if (!strncmp(result, soap_result_ok, strlen(soap_result_ok))) {
                retval = PAM_SUCCESS;
                break;
            }
        } else {
            pam_syslog(pamh, LOG_INFO, "No user input!");
        }
    }

    // cleanup
    if (otp) free(otp);
    if (curlh) curl_easy_cleanup(curlh);
    if (header_list) curl_slist_free_all(header_list);

    return retval;
}

static size_t writefunc_curl (char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct response_curl *response = (struct response_curl *) userdata;
    size_t handled;

    if (size * nmemb > HTTP_BUF_LEN - response->size - 1)
        return 0;

    handled = size * nmemb;
    memcpy(response->buffer + response->size, ptr, handled);
    response->size += handled;

    return handled;
}
