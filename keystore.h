/*
 * key_util.h
 *
 *  Created on: Aug 6, 2019
 *      Author: mengguang
 */

#ifndef KEY_UTIL_H_
#define KEY_UTIL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool generate_new_key(uint8_t *private_key);

bool generate_keystore_text_from_secret_key(const uint8_t *secret_key,
                                            const char *password, char *keystore_text);

bool get_secret_key_from_keystore_text(const char *keystore_text,
                                       const char *password, uint8_t *secret_key);
bool get_address_from_keystore_text(const char *keystore_text, char *address);
#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* KEY_UTIL_H_ */
