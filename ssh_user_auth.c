#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "ssh_user_auth.h"

const char * get_ssh_user_auth(pam_handle_t * pamh, int debug)
{
    const char * ssh_user_auth;

    ssh_user_auth = pam_getenv(pamh, "SSH_USER_AUTH");
    if (ssh_user_auth == NULL) {
        DBG(pamh, debug, "no SSH_USER_AUTH");
        return NULL;
    }
    if (strlen(ssh_user_auth) == 0) {
        DBG(pamh, debug, "empty SSH_USER_AUTH");
        return NULL;
    }
    return ssh_user_auth;
}

char * extract_details(pam_handle_t * pamh, int debug, const char * method)
{
    char *my_ssh_user_auth, *tok, *saveptr;
    char *details = NULL;
    size_t method_len = strlen(method);

    const char *ssh_user_auth = get_ssh_user_auth(pamh, debug);
    if (ssh_user_auth == NULL)
        return NULL;

    my_ssh_user_auth = strdup(ssh_user_auth);
    if (my_ssh_user_auth == NULL) {
        ERR(pamh, "SSH extract details: unable to strdup");
        return NULL;
    }

    tok = strtok_r(my_ssh_user_auth, ",", &saveptr);
    while (tok != NULL) {
        while (*tok == ' ')
            ++tok;
        if (strncmp(tok, method, method_len) == 0)
            break;
        tok = strtok_r(NULL, ",", &saveptr);
    }

    if (tok != NULL) {
        tok += method_len;
        if (*tok != ':' || *(tok + 1) != ' ') {
            DBG(pamh, debug, "empty details in SSH_USER_AUTH");
        } else {
            details = strdup(tok + 2);
            if (details == NULL) {
                ERR(pamh, "SSH extract details: unable to strdup");
            }
        }
    }

    free(my_ssh_user_auth);
    return details;
}
