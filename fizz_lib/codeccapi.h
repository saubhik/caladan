#include <stddef.h>
#include <stdint.h>

struct MyCipherC;
typedef struct MyCipherC MyCipherC;

// TODO: handlers

MyCipherC *MyCipherC_create(void *key, size_t keylen, void *iv, size_t ivlen);

void MyCipherC_destroy(MyCipherC *cipher);

void *MyCipherC_encrypt(MyCipherC *cipher, void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo);

void *MyCipherC_decrypt(MyCipherC *cipher, void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo);