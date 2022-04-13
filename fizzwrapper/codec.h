#pragma once

#include <fizz/server/FizzServer.h>

#include "Aead.h"
#include "CryptoFactory.h"
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
	Ciphers();
	~Ciphers();

	void computeCiphers(CipherKind kind, folly::ByteRange secret);

//	void *encrypt(
//		void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);

//	void *decrypt(
//		void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);

 private:
//	std::unique_ptr<Aead> cipher;
	fizz::server::State state_;
	FizzCryptoFactory cryptoFactory_;

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

	std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
	buildCiphers(folly::ByteRange secret);
	void createServerCtx();
};

} // namespace quic
