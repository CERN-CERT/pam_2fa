#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include "pam_2fa.h"
#include "ssh_user_auth.h"

#define BUFF_LEN 2048

static int open_trusted_file(pam_handle_t * pamh, const module_config *cfg, const struct passwd* user)
{
    int fd;
    char *filename;
    struct stat st;

    if (asprintf(&filename, "%s/%s", user->pw_dir, cfg->trusted_file) < 0) {
        pam_syslog(pamh, LOG_CRIT, "Can't allocate filename buffer");
        return -1;
    }

    fd = open(filename, O_RDONLY);
    if(fd < 0) {
        pam_syslog(pamh, LOG_ERR, "Can't open file '%s'", filename);
        goto err;
    }
    if (fstat(fd, &st) < 0) {
        pam_syslog(pamh, LOG_ERR, "Can't get stats of file '%s'", filename);
        goto err_fd;
    }
    if (!S_ISREG(st.st_mode)) {
        pam_syslog(pamh, LOG_ERR, "Not a regular file '%s'", filename);
        goto err_fd;
    }
    free(filename);
    return fd;
err_fd:
    close(fd);
err:
    free(filename);
    return -1;
}

static int cut_principal(pam_handle_t * pamh, const module_config *cfg, char *input) {
    char *kerberos_domain;
    
    kerberos_domain = strchr(input, '@');
    if (kerberos_domain != NULL && strcmp(kerberos_domain + 1, cfg->domain) == 0) {
        *kerberos_domain = '\0';
        return 1;
    }
    pam_syslog(pamh, LOG_ERR, "Kerberos principal does not have expected domain, ignoring : '%s'", input);
    return 0;
}

static int compare_user(pam_handle_t * pamh, const module_config *cfg, const char *username, char *input) {
    if (input[0] == '#') {
        return 0;
    }
    if (cfg->domain) {
        if (!cut_principal(pamh, cfg, input)) {
            return 0;
        }
    }
    return !strcmp(username, input);
}

static int validate_real_user(pam_handle_t * pamh, const module_config *cfg, const struct passwd *user, const char *username)
{
    struct pam_2fa_privs p;
    int fd;
    char *buffer, *buf_pos, *buf_next_line;
    size_t remaining;
    ssize_t bytes_read;
    int retval = -1;

    if (pam_2fa_drop_priv(pamh, &p, user) < 0) {
        return -1;
    }
    fd = open_trusted_file(pamh, cfg, user);
    if (fd < 0) {
        goto clean;
    }
    
    buffer = (char*) calloc(BUFF_LEN, 1);
    if (buffer == NULL) {
        goto clean_fd;
    }

    buf_pos = buffer;
    /* buf_pos is at most at buffer + BUFF_LEN / 2, so BUFF_LEN - (buf_pos - buffer) - 1 > 0 */
    while ((bytes_read = read(fd, buf_pos, (size_t)(BUFF_LEN - (buf_pos - buffer) - 1))) > 0) {
        buf_pos[bytes_read] = '\0'; /* Due to the '- 1' above, there is always space for this char */
        buf_pos = buffer;
        while ((buf_next_line = strchr(buf_pos, '\n'))) {
            *(buf_next_line) = 0;
            ++buf_next_line;
            if (compare_user(pamh, cfg, username, buf_pos) > 0) {
                retval = 1;
                pam_syslog(pamh, LOG_INFO, "Authenticating '%s' as '%s' (validated from trusted file)", user->pw_name, username);
                goto clean_buffer;
            }
            buf_pos = buf_next_line;
        }
        remaining = strlen(buf_pos);
        if (remaining > BUFF_LEN / 2) {
            pam_syslog(pamh, LOG_ERR, "Trusted file lines are too long!");
            goto clean_buffer;
        }
        memmove(buffer, buf_pos, remaining);
        buf_pos = buffer + remaining;
    }
    pam_syslog(pamh, LOG_ERR, "Got an invalid username for account '%s': '%s'", user->pw_name, username);

clean_buffer:
    free(buffer);
clean_fd:
    close(fd);
clean:
    pam_2fa_regain_priv(pamh, &p, user);
    return retval;
}

static char * get_real_user(pam_handle_t * pamh, const module_config *cfg, const struct passwd *user)
{
    char *username = NULL;

    pam_info(pamh, "You logged-in as the service account '%s', we need to know who you are for 2nd factor authentication\n", user->pw_name);
    if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &username, "login: ") != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "Unable to get real username for account '%s'", user->pw_name);
        pam_error(pamh, "Unable to get user input");
        return NULL;
    }
    if (validate_real_user(pamh, cfg, user, username) < 0) {
        free(username);
        return NULL;
    }

    return username;
}

char * get_user(pam_handle_t * pamh, const module_config *cfg)
{
    const char *username;
    char *kerberos_principal;
    struct passwd *user_entry;
    
    if (pam_get_item(pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS) {
        DBG(("Unable to retrieve username!"))
        return NULL;
    }
    DBG(("username from PAM = %s", username))

    if (cfg->domain != NULL) {
        kerberos_principal = extract_details(pamh, cfg->debug, "gssapi-with-mic");
        if (kerberos_principal != NULL) {
            if (cut_principal(pamh, cfg, kerberos_principal)) {
                pam_syslog(pamh, LOG_INFO, "Authenticating '%s' as '%s' due to kerberos ticket", username, kerberos_principal);
                /* Kerberos user: not a local system account */
                return kerberos_principal;
            } else {
              free(kerberos_principal);
            }
        }
    }

    user_entry = pam_modutil_getpwnam(pamh, username);
    if (user_entry == NULL) {
        pam_syslog(pamh, LOG_ERR, "Can't get passwd entry for '%s'", username);
    }

    if (user_entry->pw_uid >= 1000) {
        /* User account: no need to change user */
        return strdup(username);
    }

    return get_real_user(pamh, cfg, user_entry);
}
