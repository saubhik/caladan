#pragma once

#include "Aead.h"
#include "PacketNumberCipher.h"

using namespace folly;
using namespace fizz;

namespace quic {

enum class CipherKind {
	HandshakeRead,
	HandshakeWrite,
	OneRttRead,
	OneRttWrite,
	ZeroRttRead,
};

class Ciphers {
 public:
	Ciphers(CipherKind kind, folly::ByteRange secret);

	~Ciphers();

//	void *encrypt(
//		void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);

//	void *decrypt(
//		void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);

 private:
//	std::unique_ptr<Aead> cipher;
	std::unique_ptr<Aead> handshakeReadCipher_;
	std::unique_ptr<Aead> handshakeWriteCipher_;
	std::unique_ptr<Aead> oneRttReadCipher_;
	std::unique_ptr<Aead> oneRttWriteCipher_;
	std::unique_ptr<Aead> zeroRttReadCipher_;

	std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> zeroRttReadHeaderCipher_;
};

} // namespace quic
