/*
 * newchain.c
 *
 *  Created on: Apr 4, 2019
 *      Author: mengguang
 */

#include <ecdsa.h>
#include <nist256p1.h>
#include "newchain.h"
#include "sha3.h"
#include "string.h"
#include "memzero.h"
#include "sha2.h"
#include "misc.h"
#include "micro-ecc/uECC.h"

static const char b58digits_ordered[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define B58_MAX_BUFFER_SIZE 512
static bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
    const uint8_t *bin = data;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    while (zcount < (size_t) binsz && !bin[zcount])
        ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    if(size > B58_MAX_BUFFER_SIZE) {
        return false;
    }
    uint8_t buf[B58_MAX_BUFFER_SIZE];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < (size_t) binsz; ++i, high = j) {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < (size_t) size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j) {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    if (zcount)
        memset(b58, '1', zcount);
    for (i = zcount; j < (size_t) size; ++i, ++j)
        b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';
    *b58sz = i + 1;

    return true;
}

static int base58_encode_check(const uint8_t *data, int data_len, char *str,
                               int str_len) {
    if (data_len > 128) {
        return 0;
    }
    //uint8_t buf[data_len + 32];
    if(data_len + 32 > B58_MAX_BUFFER_SIZE) {
        return 0;
    }
    uint8_t buf[B58_MAX_BUFFER_SIZE];
    uint8_t *hash = buf + data_len;
    memcpy(buf, data, data_len);
    sha256_Raw(data, data_len, hash);
    sha256_Raw(hash, 32, hash);
    size_t res = str_len;
    bool success = b58enc(str, &res, buf, data_len + 4);
    memzero(buf, sizeof(buf));
    return success ? res : 0;
}

bool address_original_to_new(uint32_t chain_id, uint8_t *original_addr,
                             char *new_addr) {
    uint8_t data[64] = {0};
    uint8_t pos = 0;
    data[pos] = 0; //version = 0;
    pos += 1;
    if (chain_id > 0xFFFFFF) {
        //4 bytes, not supported now.
        return false;
    } else if (chain_id > 0xFFFF) {
        //3 bytes, not supported now.
        return false;
    } else if (chain_id > 0xFF) {
        data[pos] = (chain_id >> 8) & 0xFF;
        data[pos + 1] = chain_id & 0xFF;
        pos += 2;
    } else {
        data[pos] = chain_id;
        pos += 1;
    }

    memcpy(data + pos, original_addr, NEWCHAIN_ADDRESS_LENGTH);
    pos += NEWCHAIN_ADDRESS_LENGTH;

    int result = base58_encode_check(data, pos, new_addr,
                                     2 * NEWCHAIN_ADDRESS_LENGTH);
    if (result > 0) {
        return true;
    } else {
        return false;
    }
}

uint64_t rlp_read_be(const uint8_t *data, uint16_t offset, uint16_t length) {
    if (length > 8) {
        return 0;
    }
    data += offset;
    uint64_t result = 0;
    for (uint16_t i = 0; i < length; i++) {
        result <<= 8;
        result += *(data++);
    }
    return result;
}

uint32_t rlp_calculate_data_size(uint32_t length, const uint8_t *data) {
    if (length == 1 && data[0] <= 0x7f) {
        return 1;
    } else if (length <= 55) {
        return 1 + length;
    } else if (length <= 0xff) {
        return 2 + length;
    } else if (length <= 0xffff) {
        return 3 + length;
    } else {
        return 4 + length;
    }
}

uint32_t rlp_calculate_number_size(const uint64_t number) {
    if (number <= 0x7f) {
        return 1;
    } else if (number <= 0xff) {
        return 2;
    } else if (number <= 0xffff) {
        return 3;
    } else if (number <= 0xffffff) {
        return 4;
    } else if (number <= 0xffffffff) {
        return 5;
    } else if (number <= 0xffffffffff) {
        return 6;
    } else if (number <= 0xffffffffffff) {
        return 7;
    } else if (number <= 0xffffffffffffff) {
        return 8;
    } else {
        return 9;
    }
}

uint32_t rlp_write_data(uint32_t length, uint8_t *data, uint8_t *result) {
    if (length > 0xFFFFFF) {
        return 0;
    }
    uint8_t header_length = 0;
    if (length == 1 && data[0] <= 0x7f) {
        header_length = 0;
    } else if (length <= 55) {
        result[0] = 0x80 + length;
        header_length = 1;
    } else if (length <= 0xff) {
        result[0] = 0xb7 + 1;
        result[1] = length;
        header_length = 2;
    } else if (length <= 0xffff) {
        result[0] = 0xb7 + 2;
        result[1] = length >> 8;
        result[2] = length & 0xff;
        header_length = 3;
    } else {
        result[0] = 0xb7 + 3;
        result[1] = length >> 16;
        result[2] = length >> 8;
        result[3] = length & 0xff;
        header_length = 4;
    }
    memcpy(result + header_length, data, length);
    return header_length + length;
}

uint32_t rlp_write_number(const uint64_t number, uint8_t *result) {
    if (!number) {
        return rlp_write_data(0, 0, result);
    }
    uint8_t data[8];
    data[0] = (number >> 56) & 0xff;
    data[1] = (number >> 48) & 0xff;
    data[2] = (number >> 40) & 0xff;
    data[3] = (number >> 32) & 0xff;
    data[4] = (number >> 24) & 0xff;
    data[5] = (number >> 16) & 0xff;
    data[6] = (number >> 8) & 0xff;
    data[7] = (number) & 0xff;
    int offset = 0;
    while (!data[offset]) {
        offset++;
    }
    return rlp_write_data(8 - offset, data + offset, result);
}

uint32_t rlp_write_list_header(const uint32_t length, uint8_t *result) {
    if (length > 0xFFFFFF) {
        return 0;
    }
    if (length <= 55) {
        result[0] = 0xc0 + length;
        return 1;
    } else if (length <= 0xff) {
        result[0] = 0xf7 + 1;
        result[1] = length;
        return 2;
    } else if (length <= 0xffff) {
        result[0] = 0xf7 + 2;
        result[1] = length >> 8;
        result[2] = length & 0xff;
        return 3;
    } else {
        result[0] = 0xf7 + 3;
        result[1] = length >> 16;
        result[2] = length >> 8;
        result[3] = length & 0xff;
        return 4;
    }
}

uint64_t rlp_get_list_full_length(const uint8_t *data) {
    if ((data[0] >= 0xC0) && (data[0] <= 0xF7)) {
        return data[0] - 0xC0 + 1;
    }
    if ((data[0] >= 0xF8) && (data[0] <= 0xFF)) { //max 8 bytes
        return rlp_read_be(data, 1, data[0] - 0xF7) + (data[0] - 0xF7) + 1;
    }
    return 0;
}

bool newchain_build_unsigned_transaction(transaction *tx, uint8_t *result,
                                         uint32_t *result_length) {
    uint32_t data_length = 0;
    uint32_t list_length = 0;
    list_length += rlp_calculate_number_size(tx->nonce);
    list_length += rlp_calculate_number_size(tx->gasPrice);
    list_length += rlp_calculate_number_size(tx->gasLimit);
    if (tx->hasAddress) {
        list_length += rlp_calculate_data_size(20, tx->address);
    } else {
        list_length += rlp_calculate_data_size(0, 0);
    }

    list_length += rlp_calculate_data_size(tx->valueLength, tx->value);
    list_length += rlp_calculate_data_size(tx->dataLength, tx->data);
    if (tx->chainId != 0) {
        list_length += rlp_calculate_number_size(tx->chainId);
        list_length += rlp_calculate_data_size(0, 0);
        list_length += rlp_calculate_data_size(0, 0);
    }

    if (list_length > (*result_length - 4)) {
        return false;
    }

    //start to write data to result.
    data_length += rlp_write_list_header(list_length, result);
    data_length += rlp_write_number(tx->nonce, result + data_length);
    data_length += rlp_write_number(tx->gasPrice, result + data_length);
    data_length += rlp_write_number(tx->gasLimit, result + data_length);
    if (tx->hasAddress) {
        data_length += rlp_write_data(20, tx->address, result + data_length);
    } else {
        data_length += rlp_write_data(0, 0, result + data_length);
    }
    data_length += rlp_write_data(tx->valueLength, tx->value,
                                  result + data_length);
    data_length += rlp_write_data(tx->dataLength, tx->data,
                                  result + data_length);
    if (tx->chainId != 0) {
        data_length += rlp_write_number(tx->chainId, result + data_length);
        data_length += rlp_write_data(0, 0, result + data_length);
        data_length += rlp_write_data(0, 0, result + data_length);
    }
    *result_length = data_length;
    return true;
}

bool newchain_sign_transaction(const uint8_t *privateKey, const uint8_t *digest, uint8_t *signature, uint8_t *recovery_id) {
    int success = ecdsa_sign_digest(
            &nist256p1, privateKey, digest, signature, recovery_id, NULL);
    return (success == 0);
}

bool newchain_build_signed_transaction(transaction *tx, uint8_t recovery_id, uint8_t *signature, uint8_t *result,
                                       uint32_t *result_length) {
    uint32_t data_length = 0;
    uint32_t list_length = 0;
    list_length += rlp_calculate_number_size(tx->nonce);
    list_length += rlp_calculate_number_size(tx->gasPrice);
    list_length += rlp_calculate_number_size(tx->gasLimit);
    if (tx->hasAddress) {
        list_length += rlp_calculate_data_size(20, tx->address);
    } else {
        list_length += rlp_calculate_data_size(0, 0);
    }

    list_length += rlp_calculate_data_size(tx->valueLength, tx->value);
    list_length += rlp_calculate_data_size(tx->dataLength, tx->data);
    if (tx->chainId != 0) {
        uint32_t v = (tx->chainId * 2) + 35 + recovery_id;
        list_length += rlp_calculate_number_size(v);
        list_length += rlp_calculate_data_size(32, signature);
        list_length += rlp_calculate_data_size(32, signature + 32);
    }

    if (list_length > (*result_length - 4)) {
        return false;
    }

    //start to write data to result.
    data_length += rlp_write_list_header(list_length, result);
    data_length += rlp_write_number(tx->nonce, result + data_length);
    data_length += rlp_write_number(tx->gasPrice, result + data_length);
    data_length += rlp_write_number(tx->gasLimit, result + data_length);
    if (tx->hasAddress) {
        data_length += rlp_write_data(20, tx->address, result + data_length);
    } else {
        data_length += rlp_write_data(0, 0, result + data_length);
    }
    data_length += rlp_write_data(tx->valueLength, tx->value, result + data_length);
    data_length += rlp_write_data(tx->dataLength, tx->data, result + data_length);
    if (tx->chainId != 0) {
        uint32_t v = (tx->chainId * 2) + 35 + recovery_id;
        data_length += rlp_write_number(v, result + data_length);
        data_length += rlp_write_data(32, signature, result + data_length);
        data_length += rlp_write_data(32, signature + 32, result + data_length);
    }
    *result_length = data_length;
    return true;
}


bool newchain_hash_transaction(transaction *tx, uint8_t *hash) {
    uint8_t unsigned_transaction[256];
    uint32_t result_length = sizeof(unsigned_transaction);
    bool result = false;
    result = newchain_build_unsigned_transaction(tx, unsigned_transaction,
                                                 &result_length);
    if (!result) {
        return false;
    }
    keccak_256(unsigned_transaction, result_length, hash);
    return true;
}

bool newchain_hash_rlp_transaction(uint8_t *unsigned_transaction,
                                   uint32_t length, uint8_t *hash) {
    keccak_256(unsigned_transaction, length, hash);
    return true;
}

static bool newchain_set_transaction_field(transaction *transaction,
                                           uint8_t *data, uint16_t offset, uint16_t length, uint8_t *index) {

    switch (*index) {

        // nonce
        case 0:
            // Nonce is allowed to be 8 bytes.
            if (length > 8) {
                return false;
            }
            transaction->nonce = rlp_read_be(data, offset, length);
            break;

            // gasPrice
        case 1:
            // Gas Price is allowed to be 8 bytes.
            if (length > 8) {
                return false;
            }
            transaction->gasPrice = rlp_read_be(data, offset, length);
            break;
            // gasLimit
        case 2:
            // Gas limit is allowed to be 8 bytes.
            if (length > 8) {
                return false;
            }
            transaction->gasLimit = rlp_read_be(data, offset, length);
            break;

            // to
        case 3:
            if (length != 0 && length != 20) {
                return false;
            }
            transaction->address = &data[offset];
            transaction->hasAddress = (length == 20);
            break;

            // value
        case 4:
            if (length > 32) {
                return false;
            }
            transaction->value = &data[offset];
            transaction->valueLength = length;
            break;

            // data
        case 5:
            transaction->data = &data[offset];
            transaction->dataLength = length;
            break;

            // v, r, s
        case 6:
            if (length <= 4) {
                transaction->chainId = rlp_read_be(data, offset, length);;
            } else {
                transaction->chainId = 0;
            }
            break;

        case 7:
        case 8:
            return true;

            // Transactions only have 9 fields
        default:
            return false;
    }

    (*index)++;

    return true;
}

static bool newchain_decode_transaction_field(transaction *transaction,
                                              uint8_t *data, uint16_t length, uint16_t offset, uint16_t *consumed,
                                              uint8_t *index) {
    if (length == 0) {
        return false;
    }

    if (data[offset] >= 0xf8) {
        // Array with extra length prefix

        if (*index != 255) {
            return false;
        }
        *index = 0;

        uint16_t ll = (data[offset] - 0xf7);
        if (offset + 1 + ll > length) {
            return false;
        }

        uint16_t l = rlp_read_be(data, offset + 1, ll);
        if (offset + 1 + ll + l > length) {
            return false;
        }

        uint16_t childOffset = offset + 1 + ll;
        while (childOffset < offset + 1 + ll + l) {
            uint16_t childConsumed = 0;
            bool success = newchain_decode_transaction_field(transaction, data,
                                                             length, childOffset, &childConsumed, index);
            if (!success) {
                return false;
            }

            childOffset += childConsumed;
            if (childOffset > offset + 1 + ll + l) {
                return false;
            }
        }

        *consumed = 1 + ll + l;
        return true;

    } else if (data[offset] >= 0xc0) {
        // Short-ish array

        if (*index != 255) {
            return false;
        }
        *index = 0;

        uint16_t l = (data[offset] - 0xc0);
        if (offset + 1 + l > length) {
            return false;
        }

        uint16_t childOffset = offset + 1;
        while (childOffset < offset + 1 + l) {
            uint16_t childConsumed = 0;
            bool success = newchain_decode_transaction_field(transaction, data,
                                                             length, childOffset, &childConsumed, index);
            if (!success) {
                return false;
            }

            childOffset += childConsumed;
            if (childOffset > offset + 1 + l) {
                return false;
            }
        }

        *consumed = 1 + l;
        return true;

    } else if (data[offset] >= 0xb8) {
        if (*index == 255) {
            return false;
        }

        uint16_t ll = (data[offset] - 0xb7);
        if (offset + 1 + ll > length) {
            return false;
        }

        uint16_t l = rlp_read_be(data, offset + 1, ll);
        if (offset + 1 + ll + l > length) {
            return false;
        }

        bool success = newchain_set_transaction_field(transaction, data,
                                                      offset + 1 + ll, l, index);
        if (!success) {
            return false;
        }
        *consumed = 1 + ll + l;

        return true;

    } else if (data[offset] >= 0x80) {
        if (*index == 255) {
            return false;
        }

        uint16_t l = (data[offset] - 0x80);
        if (offset + 1 + l > length) {
            return false;
        }

        bool success = newchain_set_transaction_field(transaction, data,
                                                      offset + 1, l, index);
        if (!success) {
            return false;
        }
        *consumed = 1 + l;

        return true;
    }

    if (*index == 255) {
        return false;
    }

    bool success = newchain_set_transaction_field(transaction, data, offset, 1,
                                                  index);
    if (!success) {
        return false;
    }
    *consumed = 1;
    return true;
}

bool newchain_decode_transaction(transaction *transaction, uint8_t *data,
                                 uint16_t length) {

    uint8_t index = 255;
    uint16_t consumed = 0;
    uint64_t rlp_length = rlp_get_list_full_length(data);
    if (rlp_length == 0 || rlp_length > length) {
        return false;
    }
    transaction->rawData = data;
    transaction->rawDataLength = rlp_length;

    bool success = newchain_decode_transaction_field(transaction, data,
                                                     rlp_length, 0, &consumed, &index);
    if (!success || consumed != rlp_length || index != 7) {
        return false;
    }
    return true;
}

// Perform in-place division by 10
static uint8_t idiv10(uint8_t *numerator, uint8_t *lengthPtr) {
    //uint8_t quotient[*lengthPtr];
    uint8_t quotient[255];
    uint8_t quotientOffset = 0;

    // Divide by 10
    size_t length = *lengthPtr;
    for (size_t i = 0; i < length; ++i) {

        // How many input bytes to work with
        size_t j = i + 1 + (*lengthPtr) - length;
        if ((*lengthPtr) < j) {
            break;
        }

        // The next digit in the output (from numerator[0:j])
        unsigned int value = rlp_read_be(numerator, 0, j);
        quotient[quotientOffset++] = value / 10;

        // Carry down the remainder
        uint8_t numeratorOffset = 0;
        numerator[numeratorOffset++] = value % 10;

        for (uint8_t k = j; k < *lengthPtr; k++) {
            numerator[numeratorOffset++] = numerator[k];
        }

        *lengthPtr = numeratorOffset;
    }

    // Calculate the remainder
    unsigned int remainder = rlp_read_be(numerator, 0, *lengthPtr);

    // Find the first no`n-zero (so we can skip them during the copy)
    uint8_t firstNonZero = 0;
    while (firstNonZero < quotientOffset && quotient[firstNonZero] == 0) {
        firstNonZero++;
    }

    // Copy the quotient to the value (stripping leading zeros)
    for (uint8_t i = firstNonZero; i < quotientOffset; i++) {
        numerator[i - firstNonZero] = quotient[i];
    }

    // New length
    *lengthPtr = quotientOffset - firstNonZero;

    return remainder;
}

uint8_t newchain_value_to_string(uint8_t *amountWei, uint8_t amountWeiLength,
                                 uint8_t skip, char *result) {

    // The actual offset into the result string we are appending to
    uint8_t offset = 0;

    //uint8_t scratch[amountWeiLength];
    uint8_t scratch[255];
    memcpy(scratch, amountWei, amountWeiLength);

    // The digit place we are into the base-10 number
    uint8_t place = 0;

    // Whether we have hit any non-zero value yet (so we can strip trailing zeros)
    bool nonZero = false;

    do {
        unsigned int remainder = idiv10(scratch, &amountWeiLength);

        // Only add characters if we are after truncation and not a trailing zero
        if (place >= skip && (nonZero || remainder != 0 || place >= 17)) {
            if (place == 18) {
                result[offset++] = '.';
            }
            result[offset++] = '0' + remainder;
            nonZero = true;
        }

        place++;
    } while (amountWeiLength && !(amountWeiLength == 1 && scratch[0] == 0));

    // Make sure we have at least 1 whole digit (with a decimal point)
    while (place <= 18) {
        if (place >= skip && (nonZero || place >= 17)) {
            if (place == 18) {
                result[offset++] = '.';
            }
            result[offset++] = '0';
        }
        place++;
    }

    // Reverse the digits
    for (uint8_t i = 0; i < offset / 2; i++) {
        char tmp = result[i];
        result[i] = result[offset - i - 1];
        result[offset - i - 1] = tmp;
    }

    // Null termination
    result[offset++] = 0;

    return offset - 1;
}

bool newchain_private_key_to_address(const uint8_t *private_key,
                                     uint8_t *address) {
    uint8_t public_key[64];

    int result = 0;
    result = uECC_compute_public_key(private_key, public_key, uECC_secp256r1());
    if (result != 1) {
        return false;
    }

    uint8_t hashed[32];
    keccak_256(public_key, sizeof(public_key), hashed);

    memcpy(address, &hashed[12], 20);

    return true;
}

