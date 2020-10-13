//
// Created by mengguang on 2020/2/19.
//

#ifndef NEWCHAIN_TRANSACTION_BUILDER_MISC_H
#define NEWCHAIN_TRANSACTION_BUILDER_MISC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hex_load(const char *src, uint8_t *target, uint32_t target_length);
void hex_dump(const char *label, const uint8_t *data, uint32_t data_length);
void hex_to_bin_length(const char *src, int src_len, uint8_t *target, int *target_length);
#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif //NEWCHAIN_TRANSACTION_BUILDER_MISC_H
