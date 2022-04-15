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

void CiphersC_computeCiphers(CiphersC *cip, uint8_t *buf, ssize_t bufLen) {
	uint64_t aeadHashIndex;
	uint64_t headerCipherHashIndex;
	std::vector<uint8_t> secret(bufLen - 16);
	memcpy(&aeadHashIndex, buf, 8);
	memcpy(&headerCipherHashIndex, buf + 8, 8);
	memcpy(&secret[0], buf + 16, bufLen - 16);
	quic::Ciphers *ciphers = reinterpret_cast<quic::Ciphers *>(cip);
	ciphers->computeCiphers(
		secret,
		aeadHashIndex,
		headerCipherHashIndex);
}

void CiphersC_destroy(CiphersC *cipher) {
	quic::Ciphers *cppcipher = reinterpret_cast<quic::Ciphers *>(cipher);
	delete cppcipher;
}

}
