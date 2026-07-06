#ifndef CONFIG_H
#define CONFIG_H

#include <sys/types.h>


typedef struct {
    int permit;     // 1 = permit, 0 = deny
    int nopass;     // 1 = no password required for this rule
    int is_group;   // 1 = ident is a group name, 0 = username
    char* ident;
    char* cmd;      // NULL = any command, else required absolute path
    char** args;    // NULL = any args, else exact argv[2..] to match
    int nargs;
} rule_t;

typedef struct {
    rule_t* rules;
    size_t count;
} ruleset_t;

// load and parse a please.conf file
int config_load(const char *path, ruleset_t *out);
void config_free(ruleset_t *rs);

// evaluate rules top to bottom. returns 1 (permit) or 0 (deny).
int config_check(const ruleset_t *rs, const char *username,
                  const gid_t *groups, int ngroups,
                  const char *cmd_path, char **cmd_args, int nargs,
                  int *out_nopass);


#endif/*CONFIG_H*/
