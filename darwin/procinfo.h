#ifndef PROCINFO_H
#define PROCINFO_H

#include <stdint.h>

typedef struct {
    int ppid;
    uint64_t start_sec;
    uint64_t start_usec;
} pi_bsdinfo;

int pi_get_bsdinfo(int pid, pi_bsdinfo *out);
char *pi_get_path(int pid);
char *pi_get_args(int pid, int *outLen);
char *pi_get_signer(int pid);

#endif
