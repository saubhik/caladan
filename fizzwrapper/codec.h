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
