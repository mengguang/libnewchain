//
// Created by mengguang on 2020/2/24.
//

#ifndef NEWCHAIN_TRANSACTION_BUILDER_PORTABLE_UTILS_H
#define NEWCHAIN_TRANSACTION_BUILDER_PORTABLE_UTILS_H
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>

bool check_and_create_wallet_dir(const char *dir);
void SetStdinEcho(bool enable);

bool read_keystore_file(const char *keystore_file_path, char *keystore_text, size_t *keystore_length);
bool write_keystore_file(const char *keystore_file_path, char *keystore_text, size_t keystore_length);

#endif //NEWCHAIN_TRANSACTION_BUILDER_PORTABLE_UTILS_H
