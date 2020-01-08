#ifndef HEADER_PAM_2FA_CURL_H
#define HEADER_PAM_2FA_CURL_H

#include "pam_2fa.h"
#include <curl/curl.h>

// Initialize curl when loading the shared library
void __module_load(void)   __attribute__((constructor));
void __module_unload(void) __attribute__((destructor));

struct pam_curl_state;

struct pam_curl_state* pam_curl_init(pam_handle_t * pamh, module_config * cfg);
void pam_curl_cleanup(struct pam_curl_state * state);
int pam_curl_set_option(struct pam_curl_state * state, CURLoption option, ...);
#define pam_curl_set_option(state, option, parameter) pam_curl_set_option(state, option, parameter)
int pam_curl_add_header(struct pam_curl_state * state, const char * header);
int pam_curl_set_headers(struct pam_curl_state * state);
CURLcode pam_curl_perform(struct pam_curl_state * state);

#define PAM_CURL_DO_OR_GOTO(state, action, endpoint, ...) \
   do { \
       if (!pam_curl_##action(state, __VA_ARGS__)) { \
           goto endpoint; \
       } \
   } while (0)
#endif /* HEADER_PAM_2FA_CURL_H */

#define HTTP_BUF_LEN 256
struct curl_response {
    char buffer[HTTP_BUF_LEN];
    size_t size;
};

size_t curl_callback_ignore (char *ptr, size_t size, size_t nmemb, void *userdata);
size_t curl_callback_copy (char *ptr, size_t size, size_t nmemb, void *userdata);
