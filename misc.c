//
// Created by mengguang on 2020/2/19.
//

#include "misc.h"
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

void simple_log(int level, const char *fmt, ...) {
    if (level < LOG_LEVEL) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    if (level == LOG_DEBUG) {
        fprintf(LOG_OUTPUT, "DEBUG: ");
    }
    if (level == LOG_INFO) {
        fprintf(LOG_OUTPUT, "INFO : ");
    }
    if (level == LOG_ERROR) {
        fprintf(LOG_OUTPUT, "ERROR: ");
    }
    vfprintf(LOG_OUTPUT, fmt, args);
    va_end(args);
}

void simple_hex_dump(int level, const char *label, const uint8_t *data, uint32_t length) {
    if (level < LOG_LEVEL) {
        return;
    }
    if (level == LOG_DEBUG) {
        fprintf(LOG_OUTPUT, "DEBUG: ");
    }
    if (level == LOG_INFO) {
        fprintf(LOG_OUTPUT, "INFO : ");
    }
    if (level == LOG_ERROR) {
        fprintf(LOG_OUTPUT, "ERROR: ");
    }
    fprintf(LOG_OUTPUT, "%s\n", label);
    fprintf(LOG_OUTPUT, "0x");
    for (int i = 0; i < length; i++) {
        fprintf(LOG_OUTPUT, "%02x", data[i]);
    }
    fprintf(LOG_OUTPUT, "\n");
}

static int char_to_int(char input) {
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex_load(const char *src, uint8_t *target) {
    //skip 0x header
    if ((src[0] == '0') && (tolower(src[1]) == 'x')) {
        src += 2;
    }
    while (*src && src[1]) {
        *(target++) = char_to_int(*src) * 16 + char_to_int(src[1]);
        src += 2;
    }
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex_to_bin(const char *src, uint8_t *target) {
    hex_load(src, target);
}

void print_hex(const char *header, const uint8_t *data, uint32_t length) {
    log_debug("%s:\n", header);
    for (uint32_t i = 0; i < length; i++) {
        log_debug("%02x", data[i]);
    }
    log_debug("\n");
}

void hex_to_bin_length(const char *src, int src_len, uint8_t *target, int *target_length) {
    //skip 0x header
    int pos = 0;
    *target_length = 0;
    if ((src[0] == '0') && (tolower(src[1]) == 'x')) {
        //src += 2;
        pos += 2;
    }
    if (src_len % 2 != 0) {
        *target_length = 0;
        return;
    }

    while (pos < src_len) {
        *(target++) = char_to_int(src[pos]) * 16 + char_to_int(src[pos + 1]);
        pos += 2;
        (*target_length)++;
    }
}

