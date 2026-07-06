#define _GNU_SOURCE

#include "config.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define CACHE_DIR "/var/run/please"
#define DEFAULT_TIMEOUT 300  // 5 min
#define CONFIG_PATH "/etc/please.conf"
#define SAFE_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define MAX_GROUPS 64


// check if the cache file exists and is recent
int cache_valid(const char *username, int timeout) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", CACHE_DIR, username);
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;  // no cache
    if (!S_ISREG(st.st_mode) || st.st_uid != 0)
        return 0;  // not a plain file we own - don't trust it
    time_t now = time(NULL);
    return (now - st.st_mtime) <= timeout;
}

void update_cache(const char *username) {
    if (mkdir(CACHE_DIR, 0700) != 0 && errno != EEXIST) {
        perror("mkdir cache dir");
        return;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", CACHE_DIR, username);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        perror("cache open");
        return;
    }
    futimens(fd, NULL);
    close(fd);
}

// resolves argv[1] to an absolute, symlink-resolved path so rule matching
// and execvp agree on what binary is actually being run. returns a malloc'd
// string or NULL
char* resolve_cmd_path(const char *cmd) {
    char candidate[PATH_MAX];
    char* resolved = malloc(PATH_MAX);
    if (!resolved)
        return NULL;

    if (strchr(cmd, '/')) {
        if (realpath(cmd, resolved))
            return resolved;
        free(resolved);
        return NULL;
    }

    char pathbuf[] = SAFE_PATH;
    char *saveptr;
    for (char *dir = strtok_r(pathbuf, ":", &saveptr); dir;
         dir = strtok_r(NULL, ":", &saveptr)) {
        snprintf(candidate, sizeof(candidate), "%s/%s", dir, cmd);
        if (access(candidate, X_OK) == 0 && realpath(candidate, resolved))
            return resolved;
    }
    free(resolved);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    openlog("please", LOG_PID, LOG_AUTHPRIV);
    prctl(PR_SET_DUMPABLE, 0);

    ruleset_t rules;
    if (config_load(CONFIG_PATH, &rules) != 0) {
        return 1;
    }

    uid_t real_uid = getuid();

    if (real_uid != 0) {
        struct passwd* pw = getpwuid(real_uid);
        if (!pw) {
            perror("getpwuid");
            config_free(&rules);
            return 1;
        }

        gid_t groups[MAX_GROUPS];
        int ngroups = MAX_GROUPS;
        if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) < 0) {
            fprintf(stderr, "please: user is in too many groups\n");
            config_free(&rules);
            return 1;
        }

        char *cmd_path = resolve_cmd_path(argv[1]);

        int nopass = 0;
        int permitted = config_check(&rules, pw->pw_name, groups, ngroups,
                                      cmd_path, argv + 2, argc - 2, &nopass);
        config_free(&rules);

        if (!permitted) {
            syslog(LOG_AUTHPRIV | LOG_NOTICE, "denied: %s tried to run %s",
                   pw->pw_name, argv[1]);
            fprintf(stderr, "you are not permitted to run that dumdum :P\n");
            free(cmd_path);
            return 1;
        }

        if (!nopass && !cache_valid(pw->pw_name, DEFAULT_TIMEOUT)) {
            struct spwd* sp = getspnam(pw->pw_name);
            if (!sp) {
                if (errno == 0) {
                    fprintf(stderr, "no shadow entry for \"%s\". "
                                    "please only works with local /etc/shadow.\n",
                                    pw->pw_name);
                } else {
                    perror("getspnam");
                }
                free(cmd_path);
                return 1;
            }

            if (!sp->sp_pwdp || sp->sp_pwdp[0] == '\0' ||
                sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*') {
                fprintf(stderr, "account is locked\n");
                free(cmd_path);
                return 1;
            }

            char* pass = getpass("password: ");
            if (!pass) {
                fprintf(stderr, "failed to read password\n");
                free(cmd_path);
                return 1;
            }
            char* enc = crypt(pass, sp->sp_pwdp);
            memset(pass, 0, strlen(pass));
            if (!enc || strcmp(enc, sp->sp_pwdp) != 0) {
                syslog(LOG_AUTHPRIV | LOG_NOTICE, "auth failure for %s", pw->pw_name);
                fprintf(stderr, "auth failed\n");
                free(cmd_path);
                return 1;
            }
            update_cache(pw->pw_name);
        }

        syslog(LOG_AUTHPRIV | LOG_NOTICE, "%s ran: %s", pw->pw_name, argv[1]);
        free(cmd_path);
    } else {
        config_free(&rules);
    }

    if (setgroups(0, NULL) != 0) {
        perror("setgroups");
        return 1;
    }
    if (setgid(0) != 0 || setuid(0) != 0) {
        perror("setgid/setuid");
        return 1;
    }

    // --- sanitize ---
    setenv("PATH", SAFE_PATH, 1);
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_AUDIT");
    unsetenv("LD_DEBUG");
    unsetenv("LD_PROFILE");
    unsetenv("PYTHONPATH");
    unsetenv("PERL5LIB");
    unsetenv("BASH_ENV");
    unsetenv("ENV");

    // --- run as root ---
    execvp(argv[1], argv + 1);
    perror("execvp");
    return 1;
}
