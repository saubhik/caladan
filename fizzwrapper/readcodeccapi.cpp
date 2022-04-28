#include "decode.h"

extern "C" {
#include "readcodeccapi.h"

ReadCodecCiphersC *ReadCodecCiphersC_create() {
	try {
		return reinterpret_cast<ReadCodecCiphersC *>(new quic::ReadCodecCiphers());
	} catch (...) {
		return nullptr;
	}
}

void ReadCodecCiphersC_compute_ciphers(
	ReadCodecCiphersC *cips,
	uint8_t *buf,
	size_t bufLen) {
	auto *ciphers = reinterpret_cast<quic::ReadCodecCiphers *>(cips);
	ciphers->computeCiphers(buf, bufLen);
}

void ReadCodecCiphersC_destroy(ReadCodecCiphersC *cips) {
	auto *ciphers = reinterpret_cast<quic::ReadCodecCiphers *>(cips);
	delete ciphers;
}
}
