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

void CiphersC_compute_ciphers(CiphersC *cips, uint8_t *buf, ssize_t bufLen) {
	uint64_t aeadHashIndex;
	uint64_t headerCipherHashIndex;
	std::vector<uint8_t> secret(bufLen - 16);
	memcpy(&aeadHashIndex, buf, 8);
	memcpy(&headerCipherHashIndex, buf + 8, 8);
	memcpy(&secret[0], buf + 16, bufLen - 16);
	auto *ciphers = reinterpret_cast<quic::Ciphers *>(cips);
	ciphers->computeCiphers(
		secret,
		aeadHashIndex,
		headerCipherHashIndex);
}

void CiphersC_inplace_encrypt(
	CiphersC *cips,
	uint64_t aeadIndex,
	uint64_t packetNum,
	void *header,
	size_t headerLen,
	void *body,
	size_t bodyLen) {
	auto *ciphers = reinterpret_cast<quic::Ciphers *>(cips);
	ciphers->inplaceEncrypt(aeadIndex, packetNum, header, headerLen, body, bodyLen);
}

void CiphersC_encrypt_packet_header(
	CiphersC *cips,
	uint64_t headerCipherIndex,
	uint8_t headerForm,
	void *header,
	size_t headerLen,
	void *body,
	size_t bodyLen) {
	auto *ciphers = reinterpret_cast<quic::Ciphers *>(cips);
	ciphers->encryptPacketHeader(
		headerCipherIndex,
		static_cast<quic::HeaderForm>(headerForm),
		static_cast<uint8_t *>(header),
		headerLen,
		static_cast<uint8_t *>(body),
		bodyLen);
}

void CiphersC_destroy(CiphersC *cips) {
	auto *ciphers = reinterpret_cast<quic::Ciphers *>(cips);
	delete ciphers;
}

}
