#include <stddef.h>
#include <stdint.h>

struct CiphersC;
typedef struct CiphersC CiphersC;

CiphersC *CiphersC_create();

void CiphersC_computeCiphers(
CiphersC *cips, uint8_t cipKind, uint8_t *sec,
ssize_t secLen);

void CiphersC_destroy(CiphersC *ciphers);

#if 0
void *MyCipherC_encrypt(
	MyCipherC *cipher, void *payload, void *aad, int payload_and_tail,
	int aadlen, uint64_t seqNo);

void *MyCipherC_decrypt(
	MyCipherC *cipher, void *payload, void *aad, int payload_and_tail,
	int aadlen, uint64_t seqNo);
#endif
