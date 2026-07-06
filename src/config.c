#define _GNU_SOURCE

#include "config.h"

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_LINE 1024
#define MAX_ARGS 64


static int grow_rules(ruleset_t *rs) {
    size_t newcap = rs->count ? 2 * rs->count : 8;
    rule_t* tmp = realloc(rs->rules, newcap * sizeof(rule_t));
    if (!tmp) {
        return -1;
    }
    rs->rules = tmp;
    return 0;
}

static void free_rule(rule_t* r) {
    free(r->ident);
    free(r->cmd);
    for (int i = 0; i < r->nargs; i++) {
        free(r->args[i]);
    }
    free(r->args);
}

void config_free(ruleset_t* rs) {
    for (size_t i = 0; i < rs->count; i++) {
        free_rule(&rs->rules[i]);
    }
    free(rs->rules);
    rs->rules = NULL;
    rs->count = 0;
}

// require: file exists, is a regular file, owned by root, not writable by group or other.
static int config_file_is_safe(const char* path, FILE** out) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "please: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fprintf(stderr, "please: fstat %s: %s\n", path, strerror(errno));
        fclose(f);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "please: %s is not a regular file\n", path);
        fclose(f);
        return -1;
    }
    if (st.st_uid != 0) {
        fprintf(stderr, "please: %s must be owned by root\n", path);
        fclose(f);
        return -1;
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr, "please: %s must not be group/world writable\n", path);
        fclose(f);
        return -1;
    }
    *out = f;
    return 0;
}

int config_load(const char* path, ruleset_t* out) {
    out->rules = NULL;
    out->count = 0;

    FILE* f;
    if (config_file_is_safe(path, &f) != 0) {
        return -1;
    }

    char line[MAX_LINE];
    int lineno = 0;
    int ok = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char* saveptr;
        char* tok = strtok_r(line, " \t\r\n", &saveptr);
        if (!tok || tok[0] == '#') continue;

        rule_t r = {0};

        if (strcmp(tok, "permit") == 0) {
            r.permit = 1;
        } else if (strcmp(tok, "deny") == 0) {
            r.permit = 0;
        } else {
            fprintf(stderr, "please.conf:%d: expected \"permit\" or \"deny\", got \"%s\"\n", lineno, tok);
            goto fail;
        }

        tok = strtok_r(NULL, " \t\r\n", &saveptr);
        if (!tok) {
            fprintf(stderr, "please.conf:%d: missing identity\n", lineno);
            goto fail;
        }
        if (strcmp(tok, "nopass") == 0) {
            r.nopass = 1;
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!tok) {
                fprintf(stderr, "please.conf:%d: missing identity after \"nopass\"\n", lineno);
                goto fail;
            }
        }

        if (tok[0] == ':') {
            if (tok[1] == '\0') {
                fprintf(stderr, "please.conf:%d: empty group name\n", lineno);
                goto fail;
            }
            r.is_group = 1;
            r.ident = strdup(tok + 1);
        } else {
            r.is_group = 0;
            r.ident = strdup(tok);
        }
        if (!r.ident) {
            fprintf(stderr, "please.conf:%d: out of memory\n", lineno);
            goto fail;
        }

        tok = strtok_r(NULL, " \t\r\n", &saveptr);
        if (tok) {
            if (strcmp(tok, "cmd") != 0) {
                fprintf(stderr, "please.conf:%d: expected \"cmd\", got \"%s\"\n", lineno, tok);
                free_rule(&r);
                goto fail;
            }
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!tok) {
                fprintf(stderr, "please.conf:%d: missing path after 'cmd'\n", lineno);
                free_rule(&r);
                goto fail;
            }
            if (tok[0] != '/') {
                fprintf(stderr, "please.conf:%d: cmd path must be absolute\n", lineno);
                free_rule(&r);
                goto fail;
            }
            r.cmd = strdup(tok);

            char* argtoks[MAX_ARGS];
            int n = 0;
            while (n < MAX_ARGS && (tok = strtok_r(NULL, " \t\r\n", &saveptr)) != NULL) {
                argtoks[n++] = tok;
            }
            if (n > 0) {
                r.args = calloc((size_t)n, sizeof(char *));
                if (!r.args) {
                    fprintf(stderr, "please.conf:%d: out of memory\n", lineno);
                    free_rule(&r);
                    goto fail;
                }
                for (int i = 0; i < n; i++) {
                    r.args[i] = strdup(argtoks[i]);
                }
                r.nargs = n;
            }
        }

        if (out->count % 8 == 0 && grow_rules(out) != 0) {
            fprintf(stderr, "please.conf:%d: out of memory\n", lineno);
            free_rule(&r);
            goto fail;
        }
        out->rules[out->count++] = r;
    }

    ok = 1;

fail:
    fclose(f);
    if (!ok) {
        config_free(out);
        return -1;
    }
    return 0;
}

static int ident_matches(const rule_t* r, const char* username, const gid_t* groups, int ngroups) {
    if (!r->is_group) {
        return strcmp(r->ident, username) == 0;
    }

    struct group* g = getgrnam(r->ident);
    if (!g) {
        return 0;
    }
    for (int i = 0; i < ngroups; i++) {
        if (groups[i] == g->gr_gid) {
            return 1;
        }
    }
    return 0;
}

static int cmd_matches(const rule_t* r, const char* cmd_path, char** cmd_args, int nargs) {
    if (!r->cmd) return 1;
    if (!cmd_path || strcmp(r->cmd, cmd_path) != 0) return 0;
    if (!r->args) return 1;
    if (r->nargs != nargs) return 0;
    for (int i = 0; i < nargs; i++) {
        if (strcmp(r->args[i], cmd_args[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

int config_check(const ruleset_t* rs, const char* username,
                 const gid_t* groups, int ngroups,
                 const char* cmd_path, char** cmd_args, int nargs,
                 int* out_nopass)
{
    int matched = -1;
    int nopass = 0;

    for (size_t i = 0; i < rs->count; i++) {
        rule_t* r = &rs->rules[i];
        if (!ident_matches(r, username, groups, ngroups)) {
            continue;
        }
        if (!cmd_matches(r, cmd_path, cmd_args, nargs)) {
            continue;
        }
        matched = r->permit;
        nopass = r->nopass;
    }

    if (matched != 1) {
        return 0;
    }
    *out_nopass = nopass;
    return 1;
}
