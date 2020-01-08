#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <pwd.h>
#include <grp.h>
#include <sys/fsuid.h>

#include "pam_2fa.h"

/*
 * Two setfsuid() calls in a row are necessary to check
 * whether setfsuid() succeeded or not.
 */
static int change_uid(uid_t uid, uid_t *save)
{
    uid_t tmp = (uid_t) setfsuid(uid);
    if (save)
        *save = tmp;
    return (uid_t) setfsuid(uid) == uid ? 0 : -1;
}
static int change_gid(gid_t gid, gid_t *save)
{
    gid_t tmp = (gid_t) setfsgid(gid);
    if (save)
        *save = tmp;
    return (gid_t) setfsgid(gid) == gid ? 0 : -1;
}

static void cleanup(struct pam_2fa_privs *p)
{
    if (p && p->grplist) {
        free(p->grplist);
        p->grplist = NULL;
        p->nbgrps = 0;
    }
}

#define PRIV_MAGIC            0x1004000a
#define PRIV_MAGIC_DONOTHING  0xdead000a

int pam_2fa_drop_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw)
{
    int res;
    memset(p, 0, sizeof(struct pam_2fa_privs));

    /*
     * If not root, we can do nothing.
     * If switching to root, we have nothing to do.
     * That is, in both cases, we do not care.
     */
    if (geteuid() != 0 || pw->pw_uid == 0) {
        p->is_dropped = PRIV_MAGIC_DONOTHING;
        return 0;
    }

    res = getgroups(0, NULL);
    if (res < 0) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_drop_priv: getgroups failed: %m");
        return -1;
    }

    p->grplist = (gid_t *) calloc((size_t) res, sizeof(gid_t));
    if (!p->grplist) {
        pam_syslog(pamh, LOG_ERR, "out of memory");
        return -1;
    }
    p->nbgrps = res;

    res = getgroups(p->nbgrps, p->grplist);
    if (res < 0) {
        pam_syslog(pamh, LOG_ERR,
               "pam_2fa_drop_priv: getgroups failed: %m");
        cleanup(p);
        return -1;
    }

    /*
     * We should care to leave process credentials in consistent state.
     * That is, e.g. if change_gid() succeeded but change_uid() failed,
     * we should try to restore old gid.
     */
    if (setgroups(0, NULL)) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_drop_priv: setgroups failed: %m");
        cleanup(p);
        return -1;
    }
    if (change_gid(pw->pw_gid, &p->old_gid)) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_drop_priv: change_gid failed: %m");
        (void) setgroups((size_t) p->nbgrps, p->grplist);
        cleanup(p);
        return -1;
    }
    if (change_uid(pw->pw_uid, &p->old_uid)) {
        pam_syslog(pamh, LOG_ERR,
               "pam_2fa_drop_priv: change_uid failed: %m");
        (void) change_gid(p->old_gid, NULL);
        (void) setgroups((size_t) p->nbgrps, p->grplist);
        cleanup(p);
        return -1;
    }

    p->is_dropped = PRIV_MAGIC;
    return 0;
}

int pam_2fa_regain_priv(pam_handle_t *pamh, struct pam_2fa_privs *p, const struct passwd *pw)
{
    switch (p->is_dropped) {
        case PRIV_MAGIC_DONOTHING:
            p->is_dropped = 0;
            return 0;

        case PRIV_MAGIC:
            break;

        default:
            pam_syslog(pamh, LOG_CRIT, "pam_2fa_regain_priv: called with invalid state");
            return -1;
        }

    /*
     * We should care to leave process credentials in consistent state.
     * That is, e.g. if change_uid() succeeded but change_gid() failed,
     * we should try to restore uid.
     */
    if (change_uid(p->old_uid, NULL)) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_regain_priv: change_uid failed: %m");
        cleanup(p);
        return -1;
    }
    if (change_gid(p->old_gid, NULL)) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_regain_priv: change_gid failed: %m");
        (void)change_uid(pw->pw_uid, NULL);
        cleanup(p);
        return -1;
    }
    if (setgroups((size_t) p->nbgrps, p->grplist)) {
        pam_syslog(pamh, LOG_ERR, "pam_2fa_regain_priv: setgroups failed: %m");
        (void)change_uid(pw->pw_uid, NULL);
        (void)change_gid(pw->pw_gid, NULL);
        cleanup(p);
        return -1;
    }

    p->is_dropped = 0;
    cleanup(p);
    return 0;
}
