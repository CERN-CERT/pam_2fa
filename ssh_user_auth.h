#ifndef __SSH_USER_AUTH__
#define __SSH_USER_AUTH__

#include <security/pam_appl.h>

const char * get_ssh_user_auth(pam_handle_t * pamh, int debug);
char * extract_details(pam_handle_t * pamh, int debug, const char * method);

#endif /* __SSH_USER_AUTH__ */
