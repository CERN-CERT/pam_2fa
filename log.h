#ifndef HEADER_PAM_2FA_LOG_H
#define HEADER_PAM_2FA_LOG_H


#include <syslog.h>

/* To enable direct debugging information for development, uncomment the next like */
//#define PAM_DEBUG
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define ERR(pamh, ...) \
    do { \
        D((__VA_ARGS__)); \
        pam_syslog(pamh, LOG_ERR, __VA_ARGS__); \
    } while (0)

#define DBG(pamh, debug, ...) \
    do { \
        D((__VA_ARGS__)); \
        if (debug) { \
            pam_syslog(pamh, LOG_DEBUG, __VA_ARGS__); \
        } \
    } while (0)

#define DBG_C(pamh, cfg, ...) DBG(pamh, cfg->debug, __VA_ARGS__)

#endif /* HEADER_PAM_2FA_LOG_H */
