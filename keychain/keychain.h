#ifndef KEYCHAIN_H
#define KEYCHAIN_H

int kc_set_item(const char *service, const char *key, const char *value);
int kc_get_item(const char *service, const char *key, char **outStr);
int kc_authenticate_user(const char *reason);
const char *kc_error_message(int status);
const char *kc_parent_process_name(void);

#endif
