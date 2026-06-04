#define _GNU_SOURCE

#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
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
            perror("getspnam");
            return 1;
        }

        char* pass = getpass("password: ");
        char* enc  = crypt(pass, sp->sp_pwdp);
        if (!enc || strcmp(enc, sp->sp_pwdp) != 0) {
            fprintf(stderr, "auth failed");
            return 1;
        }
    }

    // switch to root
    if (setgid(0) != 0 || setuid(0) != 0) {
        perror("setgid/setuid");
        return 1;
    }

    // execute command as root
    execvp(argv[1], argv + 1);
    perror("execvp");
    return 1;
}