#include <time.h>

#include "pam_2fa.h"

static char from[512] = { 0 };

static int send_mail(char *dst, char *text, module_config *cfg);
static int rnd_numb(char *otp, int length);

int sms_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp) {
    int retval = 0, trial = 0;
    char *entered_code = NULL;
    char code[cfg->otp_length + 1], dst[512], txt[2048];

    //GENERATE OTP/RANDOM CODE
    rnd_numb(code, (int) cfg->otp_length);

    //SEND CODE WITH EMAIL/SMS 
    snprintf(dst, 1024, "%s@%s", user_cfg->sms_mobile, cfg->sms_gateway);
    snprintf(txt, 2048, "%s%s", cfg->sms_text, code);

    DBG(("Mail [%s] %s: %s", dst, cfg->sms_subject, txt));
    retval = send_mail(dst, txt, cfg);
    DBG(("Return status = %d", mail_status));

    if (retval != 0) {
	syslog(LOG_ERR, "%s Failed to send authentication code by SMS!",
	       LOG_PREFIX);
	converse(pamh, cfg, "Failed to send authentication code by SMS!\n",
		 PAM_ERROR_MSG, NULL);
	return (ERROR);
    }

    retval = converse(pamh, cfg, SMS_TEXT_WAIT, PAM_TEXT_INFO, NULL);
    if (retval != OK) {
	syslog(LOG_INFO, "PAM converse error");
	return (ERROR);
    }
    //GET USER INPUT
    retval = ERROR;
    for (trial = 0; retval != OK && trial < cfg->retry; ++trial) {
	retval =
	    converse(pamh, cfg, SMS_TEXT_INSERT_INPUT, PAM_PROMPT_ECHO_ON,
		     &entered_code);
	if (retval != OK) {
	    syslog(LOG_INFO, "PAM converse error");
	    return (ERROR);
	}

	if (entered_code) {
	    DBG(("code entered = %s", entered_code));

	    // VERIFY IF VALID INPUT !
	    retval = strncmp(code, entered_code, cfg->otp_length + 1);
	    bzero(entered_code, cfg->otp_length + 1);
	    free(entered_code);

	    if (retval == 0) {
		DBG(("Correct code from user"));
		retval = OK;
	    } else {
		DBG(("INCORRRECT code from user!"));
		retval = ERROR;
	    }
	} else {
	    syslog(LOG_ERR, "No user input!");
	    retval = ERROR;
	}
    }

    bzero(code, cfg->otp_length + 1);
    retval = retval == OK ? PAM_SUCCESS : PAM_AUTH_ERR;
    return retval;
}

static int send_mail(char *dst, char *text, module_config *cfg)
{
    int ret;
    char command[4096];

    if (*from == 0) {
	gethostname(from, 512);
    }

    snprintf(command, 4096, "echo %s | mail -r '%s' -s '%s' '%s'", text,
	     from, cfg->sms_subject, dst);
    DBG(("Mail command = '%s'", command));
    ret = system(command);

    return ret;
}

static int rnd_numb(char *otp, int length)
{
    int i;
    srand((unsigned int) time(NULL));

    for (i = 0; i < length; ++i) {
	otp[i] = (char) ((int) (10 * (rand() / (RAND_MAX + 1.0))) + (int) '0');
    }
    otp[i] = 0;

    return OK;
}
