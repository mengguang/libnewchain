//
// Created by mengguang on 2020/2/19.
//

#include "misc.h"
#include <stdio.h>
#include <ctype.h>

void hex_dump(const char *label, const uint8_t *data, uint32_t data_length) {
    printf("%s\n", label);
    printf("0x");
    for (uint32_t i = 0; i < data_length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
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
// an even number of [0-9a-f] characters
void hex_load(const char *src, uint8_t *target, uint32_t target_length) {
    //skip 0x header
    if ((src[0] == '0') && (tolower(src[1]) == 'x')) {
        src += 2;
    }
    while (*src && src[1]) {
        if(target_length == 0) {
            break;
        }
        *(target++) = char_to_int(*src) * 16 + char_to_int(src[1]);
        src += 2;
        target_length--;
    }
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

