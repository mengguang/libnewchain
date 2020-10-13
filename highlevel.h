//
// Created by mengguang on 2020/10/13.
//

#ifndef LIBNEWCHAIN_HIGHLEVEL_H
#define LIBNEWCHAIN_HIGHLEVEL_H

#include "libnewchain.h"

bool newchain_recover_public_key(uint8_t *message_hash, uint8_t *signature, uint8_t v, uint8_t *public_key);

#endif //LIBNEWCHAIN_HIGHLEVEL_H
