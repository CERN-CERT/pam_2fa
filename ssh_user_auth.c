#include <stdlib.h>
#include <string.h>

#define DEBUG
#include <security/_pam_macros.h>

#include "ssh_user_auth.h"

const char * get_ssh_user_auth(pam_handle_t * pamh, int debug)
{
	const char * ssh_user_auth;

	ssh_user_auth = pam_getenv(pamh, "SSH_USER_AUTH");
	if (ssh_user_auth == NULL) {
		if (debug)
			D("no SSH_USER_AUTH");
		return NULL;
	}
	if (strlen(ssh_user_auth) == 0) {
		if (debug)
			D("empty SSH_USER_AUTH");
		return NULL;
	}
	return ssh_user_auth;
}

char * extract_details(pam_handle_t * pamh, int debug, const char * method)
{
	size_t method_len;
	const char *ssh_user_auth;
	char *my_ssh_user_auth, *tok, *saveptr, *details;

	details = NULL;
	method_len = strlen(method);

	ssh_user_auth = get_ssh_user_auth(pamh, debug);
	if (ssh_user_auth == NULL)
		return NULL;

	my_ssh_user_auth = strdup(ssh_user_auth);
	if (my_ssh_user_auth == NULL)
		return NULL;

	tok = strtok_r(my_ssh_user_auth, ",", &saveptr);
	while (tok != NULL) {
		if (*tok == ' ')
			++tok;
		if (strncmp(tok, method, method_len) == 0)
			break;
		tok = strtok_r(NULL, ",", &saveptr);
	}

	if (tok != NULL) {
		tok += method_len;
		if (*tok != ':' || *(tok + 1) != ' ') {
			D("empty details in SSH_USER_AUTH");
			goto clean;
		}
		details = strdup(tok + 2);
	}

clean:
	free(my_ssh_user_auth);
	return details;
}
