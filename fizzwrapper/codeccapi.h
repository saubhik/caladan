#include <stddef.h>
#include <stdint.h>

struct CiphersC;
typedef struct CiphersC CiphersC;

CiphersC *CiphersC_create();

void CiphersC_compute_ciphers(CiphersC *cips, uint8_t *buf, ssize_t buf_len);

void CiphersC_inplace_encrypt(
	CiphersC *cips,
	uint64_t aead_index,
	uint64_t packet_num,
	void *header,
	size_t header_len,
	void *body,
	size_t body_len);

void CiphersC_encrypt_packet_header(
	CiphersC *cips,
	uint64_t header_cipher_index,
	uint8_t header_form,
	void *header,
	size_t header_len,
	void *body,
	size_t body_len);

//void CiphersC_encrypt_packet_header(
//	CipherC *cips,
//	uint64_t header_cipher_index,
//	uint8_t header_form,
//	uint64_t header_len,
//	void* buf);

void CiphersC_destroy(CiphersC *cips);
