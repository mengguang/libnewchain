//
// Created by mengguang on 2020/2/19.
//

#ifndef NEWCHAIN_TRANSACTION_BUILDER_MISC_H
#define NEWCHAIN_TRANSACTION_BUILDER_MISC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_OUTPUT stderr
#define LOG_LEVEL   1

#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_ERROR   2

void simple_log(int level, const char *fmt, ...);

#define log_error(...) simple_log(LOG_ERROR, __VA_ARGS__)
#define log_info(...) simple_log(LOG_INFO, __VA_ARGS__)
#define log_debug(...) simple_log(LOG_DEBUG, __VA_ARGS__)

void simple_hex_dump(int level, const char *label, const uint8_t *data, uint32_t length);

#define hex_dump(a, b, c) simple_hex_dump(LOG_INFO,(a),(b),(c))
#define hex_dump_info(a, b, c) simple_hex_dump(LOG_INFO,(a),(b),(c))
#define hex_dump_error(a, b, c) simple_hex_dump(LOG_ERROR,(a),(b),(c))
#define hex_dump_debug(a, b, c) simple_hex_dump(LOG_DEBUG,(a),(b),(c))

void hex_load(const char *src, uint8_t *target);

void hex_to_bin_length(const char *src, int src_len, uint8_t *target, int *target_length);

void hex_to_bin(const char *src, uint8_t *target);

void print_hex(const char *header, const uint8_t *data, uint32_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif //NEWCHAIN_TRANSACTION_BUILDER_MISC_H
