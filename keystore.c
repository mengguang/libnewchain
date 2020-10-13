/*
 * key_util.c
 *
 *  Created on: Aug 6, 2019
 *      Author: mengguang
 */

#include "keystore.h"
#include "tiny-aes-c/tinyaes.h"
#include "pbkdf2.h"
#include "sha3.h"
#include <stdlib.h>
#include "micro-ecc/uECC.h"
#include "rand.h"
#include <string.h>
#include <stdio.h>
#include "misc.h"
#include "newchain.h"

#define JSMN_HEADER

#include "jsmn/jsmn.h"

#define PBKDF2_ITERATIONS 4096

int generate_random_data(uint8_t *data, unsigned int size);

bool generate_new_key(uint8_t *private_key) {
    uECC_set_rng(generate_random_data);

    uint8_t public_key[64];
    int result = 0;
    //retry max 64 times.
    for (int i = 0; i < 64; i++) {
        result = uECC_make_key(public_key, private_key, uECC_secp256r1());
        if (result == 1) {
            return true;
        }
    }
    return false;
}

int generate_random_data(uint8_t *data, unsigned int size) {
    random_buffer(data, size);
    return 1;
}

/**
 * generate_random_uuid - generate a random UUID
 * @uuid: where to put the generated UUID
 *
 * Random UUID interface
 *
 */
bool generate_random_uuid(uint8_t uuid[16]) {
    generate_random_data(uuid, 16);
    /* Set UUID version to 4 --- truly random generation */
    uuid[6] = (uuid[6] & 0x0Fu) | 0x40u;
    /* Set the UUID variant to DCE */
    uuid[8] = (uuid[8] & 0x3Fu) | 0x80u;
    return true;
}

/*
 * https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition#pbkdf2-sha-256
 * keystore example:
 {
 "address":"1111111111111111111111111111111111111111",
 "crypto" : {
 "cipher" : "aes-128-ctr",
 "cipherparams" : {
 "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
 },
 "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
 "kdf" : "pbkdf2",
 "kdfparams" : {
 "c" : 262144,
 "dklen" : 32,
 "prf" : "hmac-sha256",
 "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
 },
 "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
 },
 "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
 "version" : 3
 }
 */

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start
        && strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

bool get_value_from_tokens(const char *json_text, jsmntok_t *t,
                           int token_number, const char *name, uint8_t *value, int *value_len,
                           bool convert_to_binary) {
    for (int i = 1; i < token_number; i++) {
        if (jsoneq(json_text, &t[i], name) == 0) {
            uint16_t length = t[i + 1].end - t[i + 1].start;
            const char *start = json_text + t[i + 1].start;
            if (convert_to_binary == true) {
                hex_to_bin_length(start, length, value, value_len);
            } else {
                if (length > *value_len) {
                    length = *value_len;
                }
                memcpy(value, start, length);
                *value_len = length;
            }
            return true;
        }
    }
    return false;
}

#define MAX_TOKEN_SIZE 64

bool get_address_from_keystore_text(const char *keystore_text, char *address) {
    jsmn_parser p;
    jsmntok_t t[MAX_TOKEN_SIZE];

    jsmn_init(&p);
    int r = jsmn_parse(&p, keystore_text, strlen(keystore_text), t,
                       MAX_TOKEN_SIZE);
    if (r < 0) {
        printf("jsmn_parse failed: %d\n", r);
        return false;
    }
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        printf("JSON Object expected.\n");
        return false;
    }

    printf("jsmn_parse got %d tokens.\n", r);

    bool result;
    int length = NEWCHAIN_HEX_ADDRESS_LENGTH;
    result = get_value_from_tokens(keystore_text, t, r, "address", (uint8_t *) address, &length,
                                   false);
    if (result == false) {
        printf("get_value_from_tokens of address failed.\n");
        return false;
    }
    return true;
}

bool get_secret_key_from_keystore_text(const char *keystore_text,
                                       const char *password, uint8_t *secret_key) {
    jsmn_parser p;
    jsmntok_t t[MAX_TOKEN_SIZE];

    jsmn_init(&p);
    int r = jsmn_parse(&p, keystore_text, strlen(keystore_text), t,
                       MAX_TOKEN_SIZE);
    if (r < 0) {
        printf("jsmn_parse failed: %d\n", r);
        return false;
    }
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        printf("JSON Object expected.\n");
        return false;
    }

    printf("jsmn_parse got %d tokens.\n", r);

    uint8_t iv[16];
    bool result;
    int length = sizeof(iv);
    result = get_value_from_tokens(keystore_text, t, r, "iv", iv, &length,
                                   true);
    if (result == false) {
        printf("get_value_from_tokens of iv failed.\n");
        return false;
    }
    hex_dump("iv: ", iv, length);

    uint8_t cipher_bin[32];
    length = sizeof(cipher_bin);
    result = get_value_from_tokens(keystore_text, t, r, "ciphertext",
                                   cipher_bin, &length, true);
    if (result == false) {
        printf("get_value_from_tokens of ciphertext failed.\n");
        return false;
    }
    hex_dump("cipher_bin: ", cipher_bin, length);

    uint8_t salt[32];
    length = sizeof(salt);
    result = get_value_from_tokens(keystore_text, t, r, "salt", salt, &length,
                                   true);
    if (result == false) {
        printf("get_value_from_tokens of salt failed.\n");
        return false;
    }
    hex_dump("salt: ", salt, length);

    uint8_t mac[32];
    length = sizeof(mac);
    result = get_value_from_tokens(keystore_text, t, r, "mac", mac, &length,
                                   true);
    if (result == false) {
        printf("get_value_from_tokens of mac failed.\n");
        return false;
    }
    hex_dump("mac: ", mac, length);

    uint8_t derived_key[32];
    uint32_t iterations = 0;

    char iterations_text[16] = {0};
    length = sizeof(iterations_text);
    result = get_value_from_tokens(keystore_text, t, r, "c",
                                   (uint8_t *) iterations_text, &length,
                                   false);
    if (result == false) {
        printf("get_value_from_tokens of c failed.\n");
        return false;
    }
    printf("iterations: %s\n", iterations_text);

    iterations = (uint32_t) strtol(iterations_text, NULL, 10);

    if ((iterations < 4096) || (iterations > 262144)) {
        printf("invalid iterations of c: %u\n", iterations);
        return false;
    }

    pbkdf2_hmac_sha256((uint8_t *) password, (int) strlen(password), salt,
                       sizeof(salt), iterations, derived_key, sizeof(derived_key));
    hex_dump("derived_key: ", derived_key, sizeof(derived_key));

    SHA3_CTX ctx;
    keccak_256_Init(&ctx);
    keccak_Update(&ctx, derived_key + 16, 16);
    keccak_Update(&ctx, cipher_bin, sizeof(cipher_bin));
    uint8_t c_mac[32];
    keccak_Final(&ctx, c_mac);
    if (memcmp(mac, c_mac, sizeof(mac)) != 0) {
        printf("password is not correct.\n");
        return false;
    }
    printf("password is correct.\n");

    struct AES_ctx aes;
    AES_init_ctx_iv(&aes, derived_key, iv);
    AES_CTR_xcrypt_buffer(&aes, cipher_bin, sizeof(cipher_bin));
    memcpy(secret_key, cipher_bin, sizeof(cipher_bin));
    hex_dump("plain cipher: ", cipher_bin, sizeof(cipher_bin));

    uint8_t address[20];
    result = newchain_private_key_to_address(secret_key, address);
    if (result == false) {
        printf("newchain_private_key_to_address failed.\n");
        return false;
    }
    hex_dump("address: ", address, sizeof(address));

    return true;
}

int sprint_hex_from_binary(char *result, uint8_t *binary_data,
                           uint32_t data_length) {
    for (uint32_t i = 0; i < data_length; i++) {
        sprintf(result + (2 * i), "%02x", binary_data[i]);
    }
    return (int) data_length * 2;
}

/*
 * In its canonical textual representation,
 * the 16 octets of a UUID are represented as 32 hexadecimal (base-16) digits,
 * displayed in 5 groups separated by hyphens,
 * in the form 8-4-4-4-12 for a total of 36 characters (32 alphanumeric characters and 4 hyphens).
 * For example:
 * 123e4567-e89b-12d3-a456-426655440000
 */

int print_hex_uuid_from_binary(char *result, uint8_t uuid[16]) {
    int n_write = 0;

    n_write += sprint_hex_from_binary(result + n_write, uuid, 4);
    n_write += sprintf(result + n_write, "-");

    n_write += sprint_hex_from_binary(result + n_write, uuid + 4, 2);
    n_write += sprintf(result + n_write, "-");

    n_write += sprint_hex_from_binary(result + n_write, uuid + 6, 2);
    n_write += sprintf(result + n_write, "-");

    n_write += sprint_hex_from_binary(result + n_write, uuid + 8, 2);
    n_write += sprintf(result + n_write, "-");

    n_write += sprint_hex_from_binary(result + n_write, uuid + 10, 6);

    return n_write;
}

bool generate_keystore_text_from_secret_key(const uint8_t *secret_key,
                                            const char *password, char *keystore_text) {
    uint8_t iv[16];
    bool result;
    result = generate_random_data(iv, sizeof(iv));
    if (result == false) {
        return false;
    }

    uint8_t salt[32];
    result = generate_random_data(salt, sizeof(salt));
    if (result == false) {
        return false;
    }

    uint8_t address[20];
    result = newchain_private_key_to_address(secret_key, address);
    if (result != true) {
        printf("newchain_private_key_to_address failed.\n");
        return false;
    }

    uint8_t derived_key[32];
    uint32_t iterations = PBKDF2_ITERATIONS;
    pbkdf2_hmac_sha256((uint8_t *) password, strlen(password), salt,
                       sizeof(salt), iterations, derived_key, sizeof(derived_key));
    hex_dump("derived_key: ", derived_key, sizeof(derived_key));

    struct AES_ctx aes;
    uint8_t cipher_bin[32];
    memcpy(cipher_bin, secret_key, sizeof(cipher_bin));
    AES_init_ctx_iv(&aes, derived_key, iv);
    AES_CTR_xcrypt_buffer(&aes, cipher_bin, sizeof(cipher_bin));
    hex_dump("cipher_bin: ", cipher_bin, sizeof(cipher_bin));

    uint8_t mac[32];
    SHA3_CTX ctx;
    keccak_256_Init(&ctx);
    keccak_Update(&ctx, derived_key + 16, 16);
    keccak_Update(&ctx, cipher_bin, sizeof(cipher_bin));
    keccak_Final(&ctx, mac);
    hex_dump("mac: ", mac, sizeof(mac));

    uint8_t uuid[16];
    result = generate_random_uuid(uuid);
    if (result == false) {
        return false;
    }

    /*
     * https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition#pbkdf2-sha-256
     * keystore example:
     * add address to compatible with command line tools.
     {
     "address":"1111111111111111111111111111111111111111",
     "crypto" : {
     "cipher" : "aes-128-ctr",
     "cipherparams" : {
     "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
     },
     "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
     "kdf" : "pbkdf2",
     "kdfparams" : {
     "c" : 262144,
     "dklen" : 32,
     "prf" : "hmac-sha256",
     "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
     },
     "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
     },
     "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
     "version" : 3
     }
     */
    //generate keystore json text.
    uint32_t total_length = 0;
    int n_write = 0;

    //write address
    const char *json_0 = "{\"address\":\"";
    n_write = sprintf(keystore_text + total_length, "%s", json_0);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = sprint_hex_from_binary(keystore_text + total_length, address, 20);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write iv
    const char *json_1 =
            "\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"";
    n_write = sprintf(keystore_text + total_length, "%s", json_1);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = sprint_hex_from_binary(keystore_text + total_length, iv, 16);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write cipher_bin
    const char *json_2 = "\"},\"ciphertext\":\"";
    n_write = sprintf(keystore_text + total_length, "%s", json_2);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = sprint_hex_from_binary(keystore_text + total_length, cipher_bin,
                                     32);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write salt
    const char *json_3 =
            "\",\"kdf\":\"pbkdf2\",\"kdfparams\":{\"c\":%lu,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"";
    n_write = sprintf(keystore_text + total_length, json_3, PBKDF2_ITERATIONS);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = sprint_hex_from_binary(keystore_text + total_length, salt, 32);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write mac
    const char *json_4 = "\"},\"mac\":\"";
    n_write = sprintf(keystore_text + total_length, "%s", json_4);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = sprint_hex_from_binary(keystore_text + total_length, mac, 32);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write uuid
    const char *json_5 = "\"},\"id\":\"";
    n_write = sprintf(keystore_text + total_length, "%s", json_5);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    n_write = print_hex_uuid_from_binary(keystore_text + total_length, uuid);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    //write version
    const char *json_6 = "\",\"version\":3}";
    n_write = sprintf(keystore_text + total_length, "%s", json_6);
    if (n_write < 0) {
        return false;
    }
    total_length += n_write;

    return true;
}

