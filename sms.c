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

void* sms_pre_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg);
int sms_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, const char *otp, void* data);

const auth_mod sms_auth = {
    .pre_auth = &sms_pre_auth_func,
    .do_auth = &sms_auth_func,
    .name = "SMS OTP",
    .prompt = "Please put this code here: ",
    .otp_len = 0,
};

void sms_load_user_file(pam_handle_t *pamh, const module_config *cfg,
                        struct passwd *user_entry, user_config *user_cfg)
{
    int fd, retval;
    char *filename;
    char buf[SMS_MOBILE_LEN+2];
    char *buf_pos;
    size_t i, buf_rem, buf_len;
    ssize_t bytes_read;

    ssize_t filename_len = snprintf(NULL, 0, "%s/%s", user_entry->pw_dir, cfg->sms_user_file);
    if (filename_len < 0) {
        pam_syslog(pamh, LOG_DEBUG, "Can't compute length of filename");
        return;
    }
    filename = (char*) malloc(filename_len+1);
    if (NULL == filename) {
        pam_syslog(pamh, LOG_DEBUG, "Can't allocate filename buffer");
        return;
    }
    snprintf(filename, filename_len+1, "%s/%s", user_entry->pw_dir, cfg->sms_user_file);

    {
      // check the exitence of the file
      struct stat st;
      retval = stat(filename, &st);
      if (retval < 0) {
          pam_syslog(pamh, LOG_DEBUG, "Can't get stats of file '%s'", filename);
          free(filename);
          return;
      }

      if (!S_ISREG(st.st_mode)) {
          pam_syslog(pamh, LOG_ERR, "Not a regular file '%s'", filename);
          free(filename);
          return;
      }
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "Can't open file '%s'", filename);
        free(filename);
        return;
    }
    free(filename);

    buf_pos = buf;
    buf_rem = SMS_MOBILE_LEN+1;

    while ((bytes_read = read(fd, buf_pos, buf_rem)) > 0) {
        buf_pos += (size_t)bytes_read; // This is always > 0 by construct
        buf_rem = (size_t)((ssize_t)buf_rem - bytes_read);
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

void* sms_pre_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg) {
    int retval;
    char * code;
    char dst[1024], txt[2048];

    code = malloc(cfg->sms_otp_length + 1);
    if (code == NULL) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        return NULL;
    }

    //GENERATE OTP/RANDOM CODE
    rnd_numb(code, (int) cfg->sms_otp_length);

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
            free(code);
            return NULL;
        }
    }

    pam_prompt(pamh, PAM_TEXT_INFO, NULL, SMS_TEXT_WAIT);

    return code;
}

int sms_auth_func (pam_handle_t * pamh, user_config * user_cfg, module_config * cfg, const char *otp, void *data) {
    char * code;
    int retval;

    code = (char*) data;

    if (otp == NULL) {
        DBG(("Module error: auth  called without an otp"));
        free(code);
        return PAM_AUTH_ERR;
    }
    DBG(("code entered = %s", otp));

    // VERIFY IF VALID INPUT !
    retval = strncmp(code, otp, cfg->sms_otp_length + 1);
    free(code);

    if (retval == 0 && strlen(otp) == cfg->sms_otp_length) {
        DBG(("Correct code from user"));
        return PAM_SUCCESS;
    } else {
        DBG(("INCORRRECT code from user!"));
        return PAM_AUTH_ERR;
    }
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
