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

#define PAM_CURL_DO_OR_RET(state, action, errorval, ...) \
   do { \
       int tmp = pam_curl_##action(state, __VA_ARGS__); \
       if (!tmp) { \
           pam_curl_cleanup(state); \
           return errorval; \
       } \
   } while (0)
#endif /* HEADER_PAM_2FA_CURL_H */
