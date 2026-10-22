// SPDX-License-Identifier: GPL-3.0-only
//
// yara-false-positive.c — a harmless program that community YARA rules flag.
//
// It stores, as inert text, the indicator strings that five rules in the
// catalog's YARA-Forge Core pack look for, the way an indicator list, a
// detection self-test or documentation would. It never runs, formats or
// sends any of them: it prints how many indicators it holds and exits.
//
//   ESET_Mozi_Killswitch                 Mozi botnet kill-switch commands
//   ESET_Kobalos_Ssh_Credential_Stealer  Kobalos log format string (also
//                                        SIGNATURE_BASE_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer)
//   CADOSECURITY_Linux_Worm_ORCSHRED     ORCSHRED worm script names
//   CADOSECURITY_Linux_Wiper_SOLOSHRED   SOLOSHRED wiper command fragments
//
// Every match is therefore a false positive: the strings are present, the
// behavior is not.
#include <stdio.h>
#include <string.h>

struct indicator {
    const char *rule;
    const char *text;
};

// volatile keeps the table, and so every string, in the executable.
static const struct indicator *volatile table;

static const struct indicator indicators[] = {
    {"ESET_Mozi_Killswitch", "iptables -I INPUT  -p tcp --destination-port 7547 -j DROP"},
    {"ESET_Mozi_Killswitch", "iptables -I OUTPUT -p tcp --sport 30005 -j DROP"},
    {"ESET_Mozi_Killswitch", "/haha"},
    {"ESET_Mozi_Killswitch", "/usr/networks"},
    {"ESET_Kobalos_Ssh_Credential_Stealer",
     "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"},
    {"CADOSECURITY_Linux_Worm_ORCSHRED", "is_owner"},
    {"CADOSECURITY_Linux_Worm_ORCSHRED", "check_solaris"},
    {"CADOSECURITY_Linux_Worm_ORCSHRED", "disown"},
    {"CADOSECURITY_Linux_Worm_ORCSHRED", "/var/log/tasks"},
    {"CADOSECURITY_Linux_Wiper_SOLOSHRED", "printenv | grep -i \"ora\""},
    {"CADOSECURITY_Linux_Wiper_SOLOSHRED", "shred"},
    {"CADOSECURITY_Linux_Wiper_SOLOSHRED", "--no-preserve-root"},
    {"CADOSECURITY_Linux_Wiper_SOLOSHRED", "/dev/dsk"},
    {"CADOSECURITY_Linux_Wiper_SOLOSHRED", "$(ls /)"},
};

int main(void)
{
    table = indicators;
    size_t count = sizeof indicators / sizeof indicators[0];
    size_t bytes = 0;
    for (size_t i = 0; i < count; i++)
        bytes += strlen(table[i].text);
    printf("antinomie-yara-false-positive: %zu inert indicator strings (%zu bytes); "
           "nothing was executed\n",
           count, bytes);
    return 0;
}
