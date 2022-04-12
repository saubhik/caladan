#include <folly/ExceptionWrapper.h>
#include <folly/String.h>

#include <list>

#include "codec.h"
#include "CryptoFactory.h"

namespace quic {

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
buildCiphers(folly::ByteRange secret) {
// TODO(@saubhik): Fix aead.
//	auto aead = FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
//		*state_.context()->getFactory(),
//		*state_.keyScheduler(),
//		*state_.cipher(),
//		secret,
//		kQuicKeyLabel,
//		kQuicIVLabel));
	auto aead = nullptr;
	auto headerCipher = nullptr;

//	FizzCryptoFactory cryptoFactory_;
//	auto headerCipher = cryptoFactory_.makePacketNumberCipher(secret);

	return {std::move(aead), std::move(headerCipher)};
}

Ciphers::Ciphers(CipherKind kind, folly::ByteRange secret) {
	std::unique_ptr<quic::Aead> aead;
	std::unique_ptr<quic::PacketNumberCipher> headerCipher;
	std::tie(aead, headerCipher) = buildCiphers(secret);
	switch (kind) {
		case CipherKind::HandshakeRead:
			handshakeReadCipher_ = std::move(aead);
			handshakeReadHeaderCipher_ = std::move(headerCipher);
			break;
		case CipherKind::HandshakeWrite:
			handshakeWriteCipher_ = std::move(aead);
			handshakeWriteHeaderCipher_ = std::move(headerCipher);
			break;
		case CipherKind::OneRttRead:
			oneRttReadCipher_ = std::move(aead);
			oneRttReadHeaderCipher_ = std::move(headerCipher);
			break;
		case CipherKind::OneRttWrite:
			oneRttWriteCipher_ = std::move(aead);
			oneRttWriteHeaderCipher_ = std::move(headerCipher);
			break;
		case CipherKind::ZeroRttRead:
			zeroRttReadCipher_ = std::move(aead);
			zeroRttReadHeaderCipher_ = std::move(headerCipher);
			break;
		default:
			folly::assume_unreachable();
	}
}

Ciphers::~Ciphers() = default;

#if 0
MyCipher::MyCipher(std::string key, std::string iv) {
	TrafficKey trafficKey;
	cipher = OpenSSLEVPCipher::makeCipher<AESGCM128>();
	trafficKey.key = IOBuf::copyBuffer(key);
	trafficKey.iv = IOBuf::copyBuffer(iv);
	cipher->setKey(std::move(trafficKey));
}

void dummyfree(void *ptr, void *userdata) {}

// Expect that data buffer = (payload, tail), with last "overhead" bytes free
void *
MyCipher::encrypt(
	void *payload, void *aad, int payload_and_tail, int aadlen,
	uint64_t seqNo) {
	std::unique_ptr<IOBuf> plaintext = IOBuf::takeOwnership(
		payload,
		payload_and_tail,
		dummyfree);
	std::unique_ptr<IOBuf> aadbuf = IOBuf::takeOwnership(aad, aadlen, dummyfree);
	plaintext->trimEnd(cipher->getCipherOverhead());
	auto ciphertext = cipher->inplaceEncrypt(
		std::move(plaintext), aadbuf.get(),
		seqNo);
	return (void *) std::move(ciphertext).get();
}

void *
MyCipher::decrypt(
	void *payload, void *aad, int payload_and_tail, int aadlen,
	uint64_t seqNo) {
	std::unique_ptr<IOBuf> ciphertext = IOBuf::takeOwnership(
		payload,
		payload_and_tail,
		dummyfree);
	std::unique_ptr<IOBuf> aadbuf = IOBuf::takeOwnership(aad, aadlen, dummyfree);
	auto decrypted = cipher->decrypt(std::move(ciphertext), aadbuf.get(), seqNo);
	return (void *) std::move(decrypted).get();
}
#endif

} // namespace quic
