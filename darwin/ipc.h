#ifndef IPC_H
#define IPC_H

#include <stddef.h>

#define IPC_PEER_SAME_CODE 0
#define IPC_PEER_DIFFERENT_CODE 1
#define IPC_ERR_PEER_TOKEN -1
#define IPC_ERR_PEER_CODE -2
#define IPC_ERR_SELF_REQUIREMENT -3

int ipc_activate_socket(const char *name, int **fds, size_t *count);
int ipc_init_self_requirement(void);
int ipc_check_peer(int fd, int *outPid);
int ipc_peer_running(int fd, int *outErrno);

#endif
