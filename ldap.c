#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <ldap.h>

#include "pam_2fa.h"

int ldap_search_factors(pam_handle_t *pamh, const module_config * cfg, const char *username, user_config *user_cfg)
{
    LDAP *ld = NULL;
    LDAPMessage *result = NULL;
    int retval;
    size_t yk_id_pos = 0, yk_id_len = 0;
    BerElement *ber = NULL;
    char *base;
    char *attrs[2] = { cfg->ldap_attr, NULL };
    char *a = NULL;
    BerValue *servercred = NULL;
    BerValue cred = { .bv_len = 0 , .bv_val = 0 };

    int status = ldap_initialize(&ld, cfg->ldap_uri);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	pam_syslog(pamh, LOG_ERR, "Unable to connect to LDAP server");
	return ERROR_CONNECTION_LDAP_SERVER;
    }

    int protocol = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);
    status = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercred);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	pam_syslog(pamh, LOG_ERR, "Could not bind to LDAP server: %s", ldap_err2string(status));
        // cleanup ldap structure
	ldap_unbind_ext(ld, NULL, NULL);
	return ERROR_BINDING_LDAP_SERVER;
    }

    if (asprintf(&base, "CN=%s,%s", username, cfg->ldap_basedn) < 0) {
        ldap_unbind_ext(ld, NULL, NULL);
        return ERROR_ALLOCATING_BASE;
    }
    status = ldap_search_ext_s(ld, base, LDAP_SCOPE_BASE, NULL, attrs, 0, NULL,
                               NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &result);
    free(base);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	pam_syslog(pamh, LOG_ERR, "Could not search in LDAP server: %s", ldap_err2string(status));
        // cleanup ldap structure
	ldap_unbind_ext(ld, NULL, NULL);
	return ERROR_SEARCH_LDAP;
    }

    LDAPMessage *e = ldap_first_entry(ld, result);

    if (e == NULL) {
	DBG(("LDAP search: no entry"));
        // cleanup
        ldap_msgfree(result);
        ldap_unbind_ext(ld, NULL, NULL);
	return ERROR_NORESULT_LDAP;
    }

    retval = ERROR_NORESULT_LDAP;
    for (a = ldap_first_attribute(ld, e, &ber); a != NULL;
	 a = ldap_next_attribute(ld, e, ber)) {
        BerValue **val;
	BerValue **vals = ldap_get_values_len(ld, e, a);

	for (val = vals; *val; ++val) {
            char *v = (*val)->bv_val;
	    if (!strncmp (v, cfg->gauth_prefix, cfg->gauth_prefix_len)) {
		if (strlen(v + cfg->gauth_prefix_len) <= GAUTH_LOGIN_LEN) {
		    strncpy(user_cfg->gauth_login, v + cfg->gauth_prefix_len, GAUTH_LOGIN_LEN + 1);
                    user_cfg->gauth_login[GAUTH_LOGIN_LEN] = 0;
		    retval = OK;
		} else {
		    DBG(("WARNING: invalid gauth login in LDAP (too long): %s", v + cfg->gauth_prefix_len));
		}
	    } else if (!strncmp(v, cfg->yk_prefix, cfg->yk_prefix_len)) {
		if (strlen(v + cfg->yk_prefix_len) == YK_PUBLICID_LEN) {
                    retval = yk_get_publicid(pamh, v + cfg->yk_prefix_len, &yk_id_pos, &yk_id_len, &user_cfg->yk_publicids);
                    if(retval != OK) {
                        DBG(("WARNING: could not allocate memory for yubikey public id. Ignoring key"));
                    }
		} else {
		    DBG(("WARNING: invalid yubikey public id in LDAP (wrong length): %s", v + cfg->yk_prefix_len));
		}
	    }
	}

	ldap_value_free_len(vals);
        ldap_memfree(a);
    }

    if (retval != OK) {
        DBG(("Failed LDAP search"));
	pam_syslog(pamh, LOG_INFO, "Unable to look for 2nd factors for user '%s'",
                   username);
    }
    
    // cleanup
    ber_free(ber, 0);
    ldap_msgfree(result);
    ldap_unbind_ext(ld, NULL, NULL);
    return retval;
}
