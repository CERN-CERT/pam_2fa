#include <ldap.h>

#include "pam_2fa.h"

int ldap_search_factors(module_config * cfg, const char *username, user_config **user_ncfg)
{
    user_config *user_cfg = NULL;
    LDAP *ld = NULL;
    LDAPMessage *result = NULL;
    int status, retval;
    size_t yk_id_pos = 0, yk_id_len = 0;
    BerElement *ber = NULL;
    char base[1024] = { 0 };
    char *attrs[2] = { cfg->ldap_attr, NULL };
    char *a = NULL, *v = NULL;
    BerValue *servercred = NULL, **vals = NULL, **val = NULL;
    BerValue cred = { .bv_len = 0 , .bv_val = 0 };

    user_cfg = (user_config *) calloc(1, sizeof(user_config));
    if(!user_cfg)
        return ERROR;

    snprintf(base, 1024, "CN=%s,%s", username, cfg->ldap_basedn);
    status = ldap_initialize(&ld, cfg->ldap_uri);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	syslog(LOG_ERR, "Unable to connect to LDAP server");
	retval = ERROR_CONNECTION_LDAP_SERVER;
	goto done;
    }

    int protocol = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);
    status = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercred);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	syslog(LOG_ERR, "Could not bind to LDAP server: %s", ldap_err2string(status));
	retval = ERROR_BINDING_LDAP_SERVER;
	goto done;
    }

    status =
	ldap_search_ext_s(ld, base, LDAP_SCOPE_BASE, NULL, attrs, 0, NULL,
			  NULL, LDAP_NO_LIMIT, LDAP_NO_LIMIT, &result);

    if (status != LDAP_SUCCESS) {
	DBG(("LDAP error: %s", ldap_err2string(status)));
	syslog(LOG_ERR, "Could not search in LDAP server: %s", ldap_err2string(status));
	retval = ERROR_SEARCH_LDAP;
	goto done;
    }

    LDAPMessage *e = ldap_first_entry(ld, result);

    if (e == NULL) {
	DBG(("LDAP search: no entry"));
	retval = ERROR_NORESULT_LDAP;
	goto done;
    }

    retval = ERROR_NORESULT_LDAP;

    for (a = ldap_first_attribute(ld, e, &ber); a != NULL;
	 a = ldap_next_attribute(ld, e, ber)) {
	vals = ldap_get_values_len(ld, e, a);

	for (val = vals; *val; ++val) {
            v = (*val)->bv_val;
	    if (!strncmp (v, cfg->gauth_prefix, cfg->gauth_prefix_len)) {
		if (strlen(v + cfg->gauth_prefix_len) <= GAUTH_LOGIN_LEN) {
		    strncpy(user_cfg->gauth_login, v + cfg->gauth_prefix_len, GAUTH_LOGIN_LEN + 1);
		    retval = OK;
		} else {
		    DBG(("WARNING: invid gauth login in LDAP (too long): %s", v + cfg->gauth_prefix_len));
		}
	    } else if (!strncmp (v, cfg->sms_prefix, cfg->sms_prefix_len)) {
		if (strlen(v + cfg->sms_prefix_len) <= SMS_MOBILE_LEN - 1) {
		    if (v[cfg->sms_prefix_len] == '+')
			snprintf(user_cfg->sms_mobile, SMS_MOBILE_LEN, "00%s", v + cfg->sms_prefix_len + 1);
		    else
			strncpy(user_cfg->sms_mobile, v + cfg->sms_prefix_len, SMS_MOBILE_LEN + 1);

		    retval = OK;
		} else {
		    DBG(("WARNING: invid mobile number in LDAP (too long): %s", v + cfg->sms_prefix_len));
		}
	    } else if (!strncmp(v, cfg->yk_prefix, cfg->yk_prefix_len)) {
		if (strlen(v + cfg->yk_prefix_len) == YK_PUBLICID_LEN) {
                    retval = yk_get_publicid(v + cfg->yk_prefix_len, &yk_id_pos, &yk_id_len, &user_cfg->yk_publicids);
                    if(retval != OK) {
                        retval = ERROR;
                        goto done;
                    }

		    retval = OK;
		} else {
		    DBG(("WARNING: invalid yubikey public id in LDAP (wrong length): %s", v + cfg->yk_prefix_len));
		}
	    }
	}
    }

    if (retval != OK) {
        DBG(("Failed LDAP search"));
	syslog(LOG_INFO, "Unable to look for 2nd factors for user '%s'",
	       username);
	goto done;
    }
    //CLEAR...
  done:

    if (result != NULL)
	ldap_msgfree(result);
    if (ld != NULL)
	ldap_unbind_ext(ld, NULL, NULL);
    if (vals != NULL)
	ldap_value_free_len(vals);
    if (a != NULL)
	ldap_memfree(a);
    if (ber != NULL)
	ber_free(ber, 0);
    if (retval != OK) {
        free_user_config(user_cfg);
        *user_ncfg = NULL;
        return retval;
    }

    *user_ncfg = user_cfg;
    return retval;
}
