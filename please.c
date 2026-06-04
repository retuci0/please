#define _GNU_SOURCE

#include <crypt.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc, char** argv) {
    // not enough args
    if (argc < 2) {
        fprintf(stderr, "usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    // skip if already root
    if (getuid() != 0) {
        struct passwd* pw = getpwuid(getuid());
        if (!pw) {
            perror("getpwuid");
            return 1;
        }

        struct spwd* sp = getspnam(pw->pw_name);
        if (!sp) {
            if (errno == 0) {
                // no shadow entry, common with system accounts
                fprintf(stderr, "no shadow entry for \"%s\". "
                                "please only works with local /etc/shadow.\n",
                                pw->pw_name);
            } else {
                perror("getspnam");
            }
            return 1;
        }

        // prompt for password and compare hashes
        char* pass = getpass("password: ");
        char* enc  = crypt(pass, sp->sp_pwdp);
        if (!enc || strcmp(enc, sp->sp_pwdp) != 0) {
            fprintf(stderr, "auth failed\n");
            return 1;
        }
    }

    // drop all supplementary groups
    if (setgroups(0, NULL) != 0) {
        perror("setgroups");
        return 1;
    }

    // switch to root
    if (setgid(0) != 0 || setuid(0) != 0) {
        perror("setgid/setuid");
        return 1;
    }

    // sanitize env
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    //  unset dangerous variables
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_AUDIT");
    unsetenv("LD_DEBUG");
    unsetenv("LD_PROFILE");
    //  clear other variables like PYTHONPATH, PERL5LIB, etc.
    unsetenv("PYTHONPATH");
    unsetenv("PERL5LIB");
    unsetenv("BASH_ENV");
    unsetenv("ENV");

    // --- execute command as root ---
    execvp(argv[1], argv + 1);
    perror("execvp");
    return 1;
}