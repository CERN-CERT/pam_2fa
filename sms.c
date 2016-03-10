#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include "pam_2fa.h"

static char from[512] = { 0 };

static int send_mail(char *dst, char *text, module_config *cfg);
static int rnd_numb(char *otp, int length);

void sms_load_user_file(pam_handle_t *pamh, const module_config *cfg,
                        struct passwd *user_entry, user_config *user_cfg)
{
    int fd, retval;
    struct stat st;
    char filename[1024];
    char buf[SMS_MOBILE_LEN+2];
    char *buf_pos;
    size_t i, buf_rem, buf_len;
    ssize_t bytes_read;

    snprintf(filename, 1024, "%s/%s", user_entry->pw_dir, cfg->sms_user_file);

    retval = stat(filename, &st);
    if (retval < 0) {
        pam_syslog(pamh, LOG_DEBUG, "Can't get stats of file '%s'", filename);
        return;
    }

    if (!S_ISREG(st.st_mode)) {
        pam_syslog(pamh, LOG_ERR, "Not a regular file '%s'", filename);
        return;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "Can't open file '%s'", filename);
        return;
    }

    buf_pos = buf;
    buf_rem = SMS_MOBILE_LEN+1;

    while ((bytes_read = read(fd, buf_pos, buf_rem)) > 0) {
        buf_pos += (size_t)bytes_read; // This is always > 0 by construct
        buf_rem = (size_t)((ssize_t)bytes_read - bytes_read);
        *buf_pos = 0;
        if (buf_rem == 0)
            break;
    }
    close(fd);

    buf_len = (size_t)(buf_pos - buf); // This is always > 0 by construct
    if (buf_len > SMS_MOBILE_LEN) {
        pam_syslog(pamh, LOG_ERR, "SMS number too small (%li)'", buf_pos - buf);
        return;
    }

    for (i = 0; i <= buf_len && buf[i] >= '0' && buf[i] <= '9'; ++i);

    if (i != buf_len + 1 && buf[i] != '\n' && buf[i] != '\r') {
        pam_syslog(pamh, LOG_ERR, "SMS number contain non integer: \"%.*s\" '%i' %zu %zu", (int)(i+1), buf, buf[i], i, buf_len);
        return;
    }

    memcpy(user_cfg->sms_mobile, buf, i);
    user_cfg->sms_mobile[i] = 0;
}

int sms_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, char *otp) {
    int retval = 0, trial = 0;
    char *entered_code = NULL;
    char code[cfg->otp_length + 1], dst[1024], txt[2048];

    //GENERATE OTP/RANDOM CODE
    rnd_numb(code, (int) cfg->otp_length);

    if (user_cfg->sms_mobile[0]) {
        //SEND CODE WITH EMAIL/SMS 
        snprintf(dst, 1024, "%s@%s", user_cfg->sms_mobile, cfg->sms_gateway);
        snprintf(txt, 2048, "%s%s", cfg->sms_text, code);

        DBG(("Mail [%s] %s: %s", dst, cfg->sms_subject, txt));
        pam_syslog(pamh, LOG_DEBUG, "Sending SMS to %s", dst);
        retval = send_mail(dst, txt, cfg);
        DBG(("Return status = %d", retval));

        if (retval != 0) {
            pam_syslog(pamh, LOG_ERR, "%s Failed to send authentication code by SMS!",
                       LOG_PREFIX);
            pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Failed to send authentication code by SMS!\n");
            return (ERROR);
        }
    }

    pam_prompt(pamh, PAM_TEXT_INFO, NULL, SMS_TEXT_WAIT);

    //GET USER INPUT
    retval = ERROR;
    for (trial = 0; retval != OK && trial < cfg->retry; ++trial) {
	pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &entered_code,SMS_TEXT_INSERT_INPUT);

	if (entered_code) {
	    DBG(("code entered = %s", entered_code));

	    // VERIFY IF VALID INPUT !
	    retval = strncmp(code, entered_code, cfg->otp_length + 1);
	    free(entered_code);
            entered_code = NULL;

	    if (retval == 0) {
		DBG(("Correct code from user"));
		retval = OK;
	    } else {
		DBG(("INCORRRECT code from user!"));
		retval = ERROR;
	    }
	} else {
	    pam_syslog(pamh, LOG_ERR, "No user input!");
	    retval = ERROR;
	}
    }

    memset(code, 0, cfg->otp_length + 1);
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
