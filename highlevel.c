//
// Created by mengguang on 2020/10/13.
//

#include <memory.h>
#include "highlevel.h"
#include "keystore.h"
#include "libnewchain.h"
#include "trezor/ecdsa.h"
#include "trezor/nist256p1.h"


#define KEYSTORE_DIR "C:/tmp/20200220"
#define FROM_ADDRESS "9a437b2c78a4547df68bb37ae53667e826e3b670"
#define TO_ADDRESS   "8264f50ee16cc6176c29094eb9e563905336031d"

bool newchain_recover_public_key(uint8_t *message_hash, uint8_t *signature, uint8_t v, uint8_t *public_key) {
    int result = ecdsa_recover_pub_from_sig(&nist256p1, public_key, signature, message_hash, v);
    if (result == 0) {
        return true;
    } else {
        return false;
    }
}

uint32_t write_value_in_new(const uint64_t n, uint8_t *value) {
    bignum256 unit_new;
    bignum256 bignum_n;
    bignum256 prime;
    bn_zero(&prime);
    //just make a bit prime number.
    bn_setbit(&prime, 255);
    bn_read_uint64(1000000000000000000ULL, &unit_new);
    bn_read_uint64(n, &bignum_n);
    //bignum_n is the result of multiply.
    bn_multiply(&unit_new, &bignum_n, &prime);
    //bignum_n must be fully reduced.
    bn_mod(&bignum_n, &prime);
    bn_write_be(&bignum_n, value);
    uint32_t offset = 0;
    while (!value[offset]) {
        offset++;
    }
    return offset;
}


bool write_value_in_new_to_tx(transaction *tx, const uint64_t n, uint8_t *value) {
    if (tx == NULL || value == NULL) {
        return false;
    }
    uint32_t value_offset = write_value_in_new(n, value);
    tx->value = value + value_offset;
    tx->valueLength = 32 - value_offset;
    return true;
}


bool generate_new_keystore_and_save(const char *wallet_dir, const char *password, char *hex_address) {
    bool result = false;
    uint8_t secret_key[NEWCHAIN_PRIVATE_KEY_LENGTH];
    result = generate_new_key(secret_key);
    if (!result) {
        log_error("generate_new_key failed.\n");
        return false;
    }
    char keystore_text[1024] = {0};
    result = generate_keystore_text_from_secret_key(secret_key, password, keystore_text);
    memzero(secret_key, sizeof(secret_key));
    if (!result) {
        log_error("generate_keystore_text_from_secret_key failed.\n");
        return false;
    }
    char _hex_address[NEWCHAIN_HEX_ADDRESS_LENGTH + 1] = {0};
    result = get_address_from_keystore_text(keystore_text, _hex_address);
    if (!result) {
        log_error("get_address_from_keystore_text failed.\n");
        return false;
    }
    printf("Address: %s\n", _hex_address);
    if (!check_and_create_wallet_dir(wallet_dir)) {
        log_error("can not access dir: %s\n", wallet_dir);
        return false;
    }
    char keystore_file_path[128] = {0};
    snprintf(keystore_file_path, sizeof(keystore_file_path), "%s/%s", wallet_dir, _hex_address);
    result = write_keystore_file(keystore_file_path, keystore_text, strlen(keystore_text));
    if (!result) {
        log_error("write_keystore_file failed.\n");
        return false;
    }
    if (hex_address != NULL) {
        memcpy(hex_address, _hex_address, NEWCHAIN_HEX_ADDRESS_LENGTH);
    }
    return true;
}

bool load_keystore_and_get_secret_key(const char *hex_address, const char *password, uint8_t *secret_key) {
    char keystore_file_path[1024] = {0};
    snprintf(keystore_file_path, sizeof(keystore_file_path), "%s/%s", KEYSTORE_DIR, hex_address);
    bool result = false;
    char keystore_text[1024] = {0};
    size_t keystore_text_length = sizeof(keystore_text);
    result = read_keystore_file(keystore_file_path, keystore_text, &keystore_text_length);
    if (!result) {
        log_error("read_keystore_file failed.\n");
        return false;
    }
    result = get_secret_key_from_keystore_text(keystore_text, password, secret_key);
    if (!result) {
        log_error("get_secret_key_from_keystore_text failed.\n");
        return false;
    }
    return true;
}

bool validate_keystore_text(const char *keystore_text, const char *password) {
    bool result = false;
    uint8_t secret_key[NEWCHAIN_PRIVATE_KEY_LENGTH] = {0};
    result = get_secret_key_from_keystore_text(keystore_text, password, secret_key);
    if (!result) {
        log_error("get_secret_key_from_keystore_text failed.\n");
        return false;
    }
    char hex_address[NEWCHAIN_HEX_ADDRESS_LENGTH + 1] = {0};
    result = get_address_from_keystore_text(keystore_text, hex_address);
    if (!result) {
        log_error("get_secret_key_from_keystore_text failed.\n");
        return false;
    }
    uint8_t bin_address[NEWCHAIN_ADDRESS_LENGTH] = {0};
    hex_to_bin(hex_address, bin_address);
    uint8_t binary_address_from_key[NEWCHAIN_ADDRESS_LENGTH] = {0};
    result = newchain_private_key_to_address(secret_key, binary_address_from_key);
    if (!result) {
        log_error("newchain_private_key_to_address failed.\n");
        return false;
    }
    if (memcmp(bin_address, binary_address_from_key, sizeof(bin_address)) != 0) {
        log_error("Address not match, keystore validate failed.\n");
        return false;
    } else {
        return true;
    }
}

bool build_and_sign_transaction(const char *from_hex_address, const char *password,
                                const char *to_hex_address,
                                uint64_t nonce, uint64_t value_in_new,
                                uint64_t gas_price, uint64_t gas_limit,
                                uint8_t *data, uint16_t data_length,
                                uint32_t chain_id,
                                uint8_t *result_raw_tx, size_t *result_length
) {
    bool result = false;
    transaction tx;
    memset(&tx, 0, sizeof(tx));

    uint8_t value[32] = {0};
    uint8_t to_binary_address[NEWCHAIN_ADDRESS_LENGTH];
    //TODO: validate address length and format.
    hex_to_bin(to_hex_address, to_binary_address);

    uint8_t binary_private_key[NEWCHAIN_PRIVATE_KEY_LENGTH] = {0};
    result = load_keystore_and_get_secret_key(from_hex_address, password, binary_private_key);
    if (!result) {
        log_error("load_keystore_and_get_secret_key failed!\n");
        return false;
    }

    tx.nonce = nonce;
    tx.gasPrice = gas_price;
    tx.gasLimit = gas_limit;
    tx.address = to_binary_address;
    tx.hasAddress = true;

    write_value_in_new_to_tx(&tx, value_in_new, value);

    tx.dataLength = data_length;
    tx.data = data;
    tx.chainId = chain_id;

    uint8_t unsigned_transaction[1024];
    uint32_t length = sizeof(unsigned_transaction);
    result = newchain_build_unsigned_transaction(&tx, unsigned_transaction, &length);
    if (!result) {
        log_error("newchain_build_unsigned_transaction failed!\n");
        return false;
    }
    hex_dump("unsigned transaction", unsigned_transaction, length);

    uint8_t hash[NEWCHAIN_KECCAK256_LENGTH];
    result = newchain_hash_transaction(&tx, hash);
    if (!result) {
        log_error("newchain_hash_transaction failed!\n");
        return false;
    }
    uint8_t signature[NEWCHAIN_SIGNATURE_LENGTH];
    uint8_t recovery_id = 0;
    result = newchain_sign_transaction(binary_private_key, hash, signature, &recovery_id);
    if (!result) {
        log_error("newchain_sign_transaction failed!\n");
        return false;
    }
    uint8_t signed_transaction[1024];
    length = sizeof(signed_transaction);
    result = newchain_build_signed_transaction(&tx, recovery_id, signature, signed_transaction, &length);
    if (!result) {
        log_error("newchain_build_signed_transaction failed!\n");
        return false;
    }
    hex_dump("signed transaction", signed_transaction, length);
    if ((result_raw_tx != NULL) && (*result_length >= length)) {
        memcpy(result_raw_tx, signed_transaction, length);
        *result_length = length;
    }
    return true;
}

