#pragma once

#include <fizz/server/FizzServer.h>

#include "Aead.h"
#include "CryptoFactory.h"
#include "PacketNumberCipher.h"

using namespace folly;
using namespace fizz;

namespace quic {

class Ciphers {
 public:
	Ciphers();

	~Ciphers();

	void computeCiphers(
		folly::ByteRange secret,
		uint64_t aeadHashIndex,
		uint64_t headerCipherHashIndex);

	void inplaceEncrypt(
		uint64_t aeadHashIndex,
		uint64_t packetNum,
		void *header,
		size_t headerLen,
		void *body,
		size_t bodyLen);

	void encryptPacketHeader(
		uint64_t headerCipherIndex,
		HeaderForm headerForm,
		uint8_t *header,
		size_t headerLen,
		uint8_t *body,
		size_t bodyLen);

 private:
	fizz::server::State state_;
	FizzCryptoFactory cryptoFactory_;

	std::unordered_map<uint64_t, std::unique_ptr<Aead>> aeadCiphers;
	std::unordered_map<uint64_t, std::unique_ptr<PacketNumberCipher>>
		headerCiphers;

	std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
	buildCiphers(folly::ByteRange secret);

	void createServerCtx();
};

} // namespace quic
