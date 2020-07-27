#ifndef HEADER_PAM_2FA_LOG_H
#define HEADER_PAM_2FA_LOG_H


#include <syslog.h>

/* To enable direct debugging information for development, uncomment the next like */
//#define PAM_DEBUG
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define USER_ERR(pamh, flags, ...) \
    do { \
        D((__VA_ARGS__)); \
        pam_syslog(pamh, LOG_INFO, __VA_ARGS__); \
        if (!(PAM_SILENT & (unsigned int)flags)) \
            pam_error(pamh, __VA_ARGS__); \
    } while (0)

#define USER_ERR_C(pamh, cfg, ...) USER_ERR(pamh, cfg->flags, __VA_ARGS__)

#define ERR(pamh, flags, ...) \
    do { \
        D((__VA_ARGS__)); \
        pam_syslog(pamh, LOG_ERR, __VA_ARGS__); \
        if (!(PAM_SILENT & (unsigned int)flags)) \
            pam_error(pamh, "An internal error happened, please notify the admins, they will have more details!\n"); \
    } while (0)

#define ERR_sys(pamh, ...) ERR(pamh, PAM_SILENT, __VA_ARGS__)
#define ERR_C(pamh, cfg, ...) ERR(pamh, cfg->flags, __VA_ARGS__)

#define DBG(pamh, debug, ...) \
    do { \
        D((__VA_ARGS__)); \
        if (debug) { \
            pam_syslog(pamh, LOG_DEBUG, __VA_ARGS__); \
        } \
    } while (0)

#define DBG_C(pamh, cfg, ...) DBG(pamh, cfg->debug, __VA_ARGS__)

#endif /* HEADER_PAM_2FA_LOG_H */
