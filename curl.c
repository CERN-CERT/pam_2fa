#include "curl.h"

// Initialize curl when loading the shared library
void __module_load(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void __module_unload(void)
{
    curl_global_cleanup();
}

struct pam_curl_state {
    pam_handle_t * pamh;
    CURL *curlh;
    struct curl_slist *header_list;
    char curl_error[CURL_ERROR_SIZE];
    int pam_flags;
};

void pam_curl_cleanup(struct pam_curl_state * state)
{
    if (state == NULL)
        return;
    if (state->curlh != NULL)
        curl_easy_cleanup(state->curlh);
    if (state->header_list != NULL)
        curl_slist_free_all(state->header_list);
    free(state);
}

#define ERR_CURL(state, ...) ERR(state->pamh, state->pam_flags, __VA_ARGS__)

struct pam_curl_state* pam_curl_init(pam_handle_t * pamh, module_config * cfg)
{
    struct pam_curl_state * state;
    CURLcode retval;

    state = (struct pam_curl_state *) calloc(1, sizeof(struct pam_curl_state));
    if (state == NULL) {
        ERR_C(pamh, cfg, "Out of memory, unable to allocate curl state");
        return state;
    }

    state->pamh = pamh;
    state->pam_flags = cfg->flags;
    state->curlh = curl_easy_init();
    if (state->curlh == NULL) {
        ERR_CURL(state, "curl_easy_init failed");
        free(state);
        return NULL;
    }

    retval = curl_easy_setopt(state->curlh, CURLOPT_ERRORBUFFER, state->curl_error);
    if (retval != CURLE_OK) {
        ERR_CURL(state, "CURL: Unable to set error buffer");
        pam_curl_cleanup(state);
        return NULL;
    }

    if (cfg->capath) {
        PAM_CURL_DO_OR_GOTO(state, set_option, fail, CURLOPT_CAPATH, cfg->capath);
    }

    return state;
fail:
    /* Only triggered by PAM_CURL_DO_OR_GOTO on set_option, which is already logged */
    pam_curl_cleanup(state);
    return NULL;
}

int pam_curl_set_option(struct pam_curl_state * state, CURLoption option, ...)
{
    va_list arg;
    CURLcode retval;

    va_start(arg, option);
    if (option < CURLOPTTYPE_OBJECTPOINT) {
        long lval = va_arg(arg, long);
        retval = curl_easy_setopt(state->curlh, option, lval);
    } else if (option < CURLOPTTYPE_OFF_T) {
        void *pval = va_arg(arg, void *);
        retval = curl_easy_setopt(state->curlh, option, pval);
    } else {
        curl_off_t oval = va_arg(arg, curl_off_t);
        retval = curl_easy_setopt(state->curlh, option, oval);
    }

    if (retval != CURLE_OK) {
        ERR_CURL(state, "Unable to set CURL options %i: %s", option,  state->curl_error);
        return 0;
    }
    return 1;
}

int pam_curl_add_header(struct pam_curl_state * state, const char * header)
{
    struct curl_slist * tmp;

    tmp = curl_slist_append(state->header_list, header);
    if (tmp == NULL) {
        ERR_CURL(state, "Unable to append header: %s", state->curl_error);
        return 0;
    }
    state->header_list = tmp;
    return 1;
}

CURLcode pam_curl_perform(struct pam_curl_state * state) {
    CURLcode retval;

    if (state->header_list) {
        PAM_CURL_DO_OR_GOTO(state, set_option, fail, CURLOPT_HTTPHEADER, state->header_list);
    }

    retval = curl_easy_perform(state->curlh);
    if (retval == CURLE_HTTP_RETURNED_ERROR) {
        long response_code;
        if (curl_easy_getinfo(state->curlh, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK) {
            ERR_CURL(state, "Unable to get CURL response code");
        } else if (response_code >= 500) {
            ERR_CURL(state, "CURL: Server error (%li)", response_code);
        }
    } else if (retval != CURLE_OK) {
        ERR_CURL(state, "Unable to perform CURL request: %u %s", retval, state->curl_error);
    }
    return retval;
fail:
    /* Only triggered by PAM_CURL_DO_OR_GOTO on set_option, which is already logged */
    return CURLE_BAD_CALLING_ORDER;
}

/**
 * Process all the data given by curl by simply ignoring it
 */
size_t curl_callback_ignore (__attribute__((unused)) char *ptr,
                             size_t size, size_t nmemb,
                             __attribute__((unused)) void *userdata)
{
    return size * nmemb;
}

size_t curl_callback_copy (char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct curl_response *response = (struct curl_response *) userdata;
    size_t handled = size * nmemb;
    size_t remaining = HTTP_BUF_LEN - response->size - 1;

    if (size * nmemb > remaining) {
        return 0;
    }

    memcpy(response->buffer + response->size, ptr, handled);
    response->size += handled;
    response->buffer[response->size] = '\0';

    return handled;
}
