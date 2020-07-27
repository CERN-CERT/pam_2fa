#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "ssh_user_auth.h"

#ifdef RHEL7_COMPAT
#define SSH_AUTH_INFO "SSH_USER_AUTH"
#define TOKEN_SEPARATOR ","
#define DETAIL_SEPARATOR_LEN 2
#else /* !RHEL7_COMPAT */
#define SSH_AUTH_INFO "SSH_AUTH_INFO_0"
#define TOKEN_SEPARATOR "\n"
#define DETAIL_SEPARATOR_LEN 1
#endif /* RHEL7_COMPAT */

const char * get_ssh_user_auth(pam_handle_t * pamh, int debug)
{
    const char * ssh_user_auth;

    ssh_user_auth = pam_getenv(pamh, SSH_AUTH_INFO);
    if (ssh_user_auth == NULL) {
        DBG(pamh, debug, "no " SSH_AUTH_INFO);
        return NULL;
    }
    if (strlen(ssh_user_auth) == 0) {
        DBG(pamh, debug, "empty " SSH_AUTH_INFO);
        return NULL;
    }
    DBG(pamh, debug, SSH_AUTH_INFO" set to: %s", ssh_user_auth);
    return ssh_user_auth;
}

char * extract_details(pam_handle_t * pamh, int debug, int flags, const char * method)
{
    char *my_ssh_user_auth, *tok, *saveptr;
    char *details = NULL;
    size_t method_len = strlen(method);

    const char *ssh_user_auth = get_ssh_user_auth(pamh, debug);
    if (ssh_user_auth == NULL)
        return NULL;

    my_ssh_user_auth = strdup(ssh_user_auth);
    if (my_ssh_user_auth == NULL) {
        ERR(pamh, flags, "SSH extract details: unable to strdup");
        return NULL;
    }

    tok = strtok_r(my_ssh_user_auth, TOKEN_SEPARATOR, &saveptr);
    while (tok != NULL) {
        while (*tok == ' ')
            ++tok;
        if (strncmp(tok, method, method_len) == 0)
            break;
        tok = strtok_r(NULL, TOKEN_SEPARATOR, &saveptr);
    }

    if (tok != NULL) {
        tok += method_len;
#ifdef RHEL7_COMPAT
        if (*tok != ':' || *(tok + 1) != ' ') {
#else /*! RHEL7_COMPAT */
        if (*tok != ' ') {
#endif /* ?RHEL7_COMPAT */
            DBG(pamh, debug, "empty details in " SSH_AUTH_INFO);
        } else {
            details = strdup(tok + DETAIL_SEPARATOR_LEN);
            if (details == NULL) {
                ERR(pamh, flags, "SSH extract details: unable to strdup");
            }
        }
    }

    free(my_ssh_user_auth);
    return details;
}
