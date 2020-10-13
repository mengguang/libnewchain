/*
 * newchain.h
 *
 *  Created on: Apr 4, 2019
 *      Author: mengguang
 */

#ifndef NEWCHAIN_H_
#define NEWCHAIN_H_

#include <stdbool.h>
#include <stdint.h>

#define NEWCHAIN_PRIVATE_KEY_LENGTH       32
#define NEWCHAIN_PUBLIC_KEY_LENGTH        64
#define NEWCHAIN_ADDRESS_LENGTH          20
#define NEWCHAIN_HEX_ADDRESS_LENGTH     40

#define NEWCHAIN_CHECKSUM_ADDRESS_LENGTH (2 + 40 + 1)
#define NEWCHAIN_KECCAK256_LENGTH        32
#define NEWCHAIN_SIGNATURE_LENGTH        64

typedef struct {
    uint8_t *rawData;
    uint16_t rawDataLength;

    uint64_t nonce;

    uint64_t gasPrice;

    uint64_t gasLimit;

    uint8_t *address;
    bool hasAddress;

    uint8_t *value;
    uint8_t valueLength;

    uint8_t *data;
    uint16_t dataLength;

    uint32_t chainId;
} transaction;

#ifdef __cplusplus
extern "C" {
#endif


bool newchain_hash_transaction(transaction *tx, uint8_t *hash);

bool newchain_decode_transaction(transaction *transaction, uint8_t *data,
                                 uint16_t length);

bool newchain_hash_rlp_transaction(uint8_t *unsigned_transaction,
                                   uint32_t length, uint8_t *hash);

uint8_t newchain_value_to_string(uint8_t *amountWei, uint8_t amountWeiLength,
                                 uint8_t skip, char *result);

bool address_original_to_new(uint32_t chain_id, uint8_t *original_addr,
                             char *new_addr);

bool newchain_build_unsigned_transaction(transaction *tx, uint8_t *result,
                                         uint32_t *result_length);

bool newchain_private_key_to_address(const uint8_t *private_key,
                                     uint8_t *address);

bool newchain_hash_transaction(transaction *tx, uint8_t *hash);

bool
newchain_sign_transaction(const uint8_t *privateKey, const uint8_t *digest, uint8_t *signature, uint8_t *recovery_id);

bool newchain_build_signed_transaction(transaction *tx, uint8_t recovery_id, uint8_t *signature, uint8_t *result,
                                       uint32_t *result_length);


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* NEWCHAIN_H_ */
