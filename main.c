#include <stdio.h>
#include <string.h>
#include "libnewchain.h"

#include "highlevel.h"

const char *message_hash = "0x1b85d9cd435ec0e84c0105a1904ce1cd34094a94f3cc80e2ade9a9ed50081f93";
const char *signature = "0x1c704ddd843f742cd2ad4fc5be0f581498f9f8eb0fcb0cd4c0899c79a707d12417e185dc8d6bc7e391e47ceabe4a4d972d2e729effa5efcc44e9d02959c21448";
const int v = 0x0802 - (1007 * 2) - 35;


int main(int argc, char **argv) {
    uint8_t binary_message_hash[32];
    uint8_t binary_signature[64];
    hex_load(message_hash,binary_message_hash,sizeof(binary_message_hash));
    hex_load(signature,binary_signature,sizeof(binary_signature));

    uint8_t binary_public_key[65];
    memset(binary_public_key,0,sizeof(binary_public_key));
    bool result = newchain_recover_public_key(binary_message_hash,binary_signature,v,binary_public_key);
    if(result) {
        hex_dump("public key:",binary_public_key,sizeof(binary_public_key));
    } else {
        printf("newchain_recover_public_key error.\n");
    }
    return 0;

}