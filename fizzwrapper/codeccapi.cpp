#include "codec.h"

extern "C" {
#include "codeccapi.h"

CiphersC *CiphersC_create() {
	try {
		return reinterpret_cast<CiphersC *>(new quic::Ciphers());
	} catch (...) {
		return nullptr;
	}
}

void CiphersC_computeCiphers(
CiphersC *cip, uint8_t cipKind, uint8_t *sec,
ssize_t secLen) {
	std::vector<uint8_t> secret;
	secret.assign(sec, sec + secLen);
	quic::CipherKind cipherKind = static_cast<quic::CipherKind>(cipKind);
	quic::Ciphers *ciphers = reinterpret_cast<quic::Ciphers *>(cip);
	ciphers->computeCiphers(cipherKind, secret);
}

void CiphersC_destroy(CiphersC *cipher) {
	quic::Ciphers *cppcipher = reinterpret_cast<quic::Ciphers *>(cipher);
	delete cppcipher;
}

#if 0
MyCipherC *MyCipherC_create(void *key, size_t keylen, void *iv, size_t ivlen) {
	std::string skey(reinterpret_cast<char *>(key), keylen);
	std::string siv(reinterpret_cast<char *>(iv), ivlen);
	try {
		return reinterpret_cast<MyCipherC *>(new MyCipher(skey, siv));
	} catch (...) {
		return NULL;
	}
}

void MyCipherC_destroy(MyCipherC *cipher) {
	MyCipher *cppcipher = reinterpret_cast<MyCipher *>(cipher);
	delete cppcipher;
}

void *MyCipherC_encrypt(MyCipherC *cipher, void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo) {
	MyCipher *cppcipher = reinterpret_cast<MyCipher *>(cipher);
	return cppcipher->encrypt(payload, aad, payload_and_tail, aadlen, seqNo);
}

void *MyCipherC_decrypt(MyCipherC *cipher, void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo) {
	MyCipher *cppcipher = reinterpret_cast<MyCipher *>(cipher);
	return cppcipher->decrypt(payload, aad, payload_and_tail, aadlen, seqNo);
}
#endif

}
