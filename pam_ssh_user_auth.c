#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <sys/types.h>
#include <string.h>
#include <syslog.h>

// These #defines must be present according to PAM documentation
#define PAM_SM_AUTH

#include <security/pam_appl.h>  //to be correctly init, define it before including pam_modules.h
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "log.h"

#include "ssh_user_auth.h"

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
                              const char **argv)
{
    return PAM_SUCCESS;
}

// CALLED BY PAM_AUTHENTICATE
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
                                   int argc, const char **argv)
{
    int i, debug;
    const char * ssh_user_auth;

    debug = 0;
    for (i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = 1;
        } else {
            ERR(pamh, "Invalid option for pam_ssh_user_auth: %s", argv[i]);
            pam_error(pamh, "Sorry, Pam SSH_USER_AUTH is misconfigured, please contact admins!\n");
            return PAM_AUTH_ERR;
        }
    }
    if (debug) {
        DBG(pamh, 1, "pam_ssh_user_auth configuration:");
        DBG(pamh, 1, " debug => %d", debug);
    }

    ssh_user_auth = get_ssh_user_auth(pamh, debug);
    if (ssh_user_auth == NULL) {
        /* There was no SSH_USER_AUTH in the environment, which can be caused by:
         *  - This feature not being supported by the installed version of OpenSSH
         *  - No previously successful authentications
         *  Here, we will assume that we are in the latter case
         */
        return PAM_IGNORE;
    }

    /* We have no requirement on which authentication methods should be authorized
     * As we have a non-empty SSH_USER_AUTH, accept the request
     * TODO: add a parameter containing the list of authorized auth methods.
     */
    return PAM_SUCCESS;
}
