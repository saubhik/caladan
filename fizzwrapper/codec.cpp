#include <folly/ExceptionWrapper.h>
#include <folly/String.h>

#include <fizz/protocol/Protocol.h>
#include <fizz/crypto/test/TestUtil.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

#include <list>
#include <iostream>

#include "codec.h"

namespace fizz::test {

folly::ssl::EvpPkeyUniquePtr getPrivateKey(StringPiece key) {
	folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
	CHECK(bio);
	CHECK_EQ(BIO_write(bio.get(), key.data(), key.size()), key.size());
	folly::ssl::EvpPkeyUniquePtr pkey(
	PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
	CHECK(pkey);
	return pkey;
}

folly::ssl::X509UniquePtr getCert(folly::StringPiece cert) {
	folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
	CHECK(bio);
	CHECK_EQ(BIO_write(bio.get(), cert.data(), cert.size()), cert.size());
	folly::ssl::X509UniquePtr x509(
	PEM_read_bio_X509(
	bio.get(), nullptr, nullptr,
	nullptr));
	CHECK(x509);
	return x509;
}

} // namespace fizz::test

namespace quic {

#if 0
// Converts the hex encoded string to an IOBuf.
std::unique_ptr<folly::IOBuf>
toIOBuf(std::string hexData, size_t headroom = 0, size_t tailroom = 0) {
	std::string out;
	CHECK(folly::unhexlify(hexData, out));
	return folly::IOBuf::copyBuffer(out, headroom, tailroom);
}

template <typename Array>
Array hexToBytes(const folly::StringPiece hex) {
	auto bytesString = folly::unhexlify(hex);
	Array bytes;
	memcpy(bytes.data(), bytesString.data(), bytes.size());
	return bytes;
}

using SampleBytes = std::array<uint8_t, 16>;
using InitialByte = std::array<uint8_t, 1>;
using PacketNumberBytes = std::array<uint8_t, 4>;

struct CipherBytes {
	SampleBytes sample;
	InitialByte initial;
	PacketNumberBytes packetNumber;

	explicit CipherBytes(
	const folly::StringPiece sampleHex,
	const folly::StringPiece initialHex,
	const folly::StringPiece packetNumberHex)
	: sample(hexToBytes<SampleBytes>(sampleHex)),
	  initial(hexToBytes<InitialByte>(initialHex)),
	  packetNumber(hexToBytes<PacketNumberBytes>(packetNumberHex)) {}
};

struct HeaderParams {
	fizz::CipherSuite cipher;
	folly::StringPiece key;
	folly::StringPiece sample;
	folly::StringPiece packetNumberBytes;
	folly::StringPiece initialByte;
	folly::StringPiece decryptedPacketNumberBytes;
	folly::StringPiece decryptedInitialByte;
};

HeaderParams headerParams{
	fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
	folly::StringPiece{"0edd982a6ac527f2eddcbb7348dea5d7"},
	folly::StringPiece{"0000f3a694c75775b4e546172ce9e047"},
	folly::StringPiece{"0dbc195a"},
	folly::StringPiece{"c1"},
	folly::StringPiece{"00000002"},
	folly::StringPiece{"c3"}};

CipherBytes cipherBytes(
	headerParams.sample,
	headerParams.decryptedInitialByte,
	headerParams.decryptedPacketNumberBytes);
#endif

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
Ciphers::buildCiphers(folly::ByteRange secret) {
	auto cipher = fizz::CipherSuite::TLS_AES_128_GCM_SHA256;
	auto scheduler = (*state_.context()->getFactory()).makeKeyScheduler(cipher);
	auto aead = FizzAead::wrap(
		fizz::Protocol::deriveRecordAeadWithLabel(
			*state_.context()->getFactory(),
			*scheduler,
			cipher,
			secret,
			kQuicKeyLabel,
			kQuicIVLabel));

	auto headerCipher = cryptoFactory_.makePacketNumberCipher(secret);

#if 0
	auto out = aead->getFizzAead()->encrypt(
	toIOBuf(folly::hexlify("plaintext")),
	toIOBuf("").get(),
	0);

	std::cout << R"(aead->encrypt(hexlify("plaintext"),"",0) = )"
						<< folly::hexlify(out->moveToFbString().toStdString())
						<< std::endl;

	auto key = folly::unhexlify(headerParams.key);
	headerCipher->setKey(folly::range(key));
	headerCipher->encryptLongHeader(
		cipherBytes.sample,
		folly::range(cipherBytes.initial),
		folly::range(cipherBytes.packetNumber));

	std::cout << "InitialByte: "
						<< headerParams.decryptedInitialByte
						<< " ----encryptLongHeader----> "
						<< folly::hexlify(cipherBytes.initial)
						<< std::endl;
	std::cout << "PacketNumberBytes: "
						<< headerParams.decryptedPacketNumberBytes
						<< " ----encryptLongHeader----> "
						<< folly::hexlify(cipherBytes.packetNumber)
						<< std::endl;

	headerCipher->decryptLongHeader(
		cipherBytes.sample,
		folly::range(cipherBytes.initial),
		folly::range(cipherBytes.packetNumber));

	std::cout << "InitialByte: "
	          << headerParams.initialByte
	          << " ----decryptLongHeader----> "
	          << folly::hexlify(cipherBytes.initial)
	          << std::endl;
	std::cout << "PacketNumberBytes: "
	          << headerParams.packetNumberBytes
	          << " ----decryptLongHeader----> "
	          << folly::hexlify(cipherBytes.packetNumber)
	          << std::endl;
#endif

	return {std::move(aead), std::move(headerCipher)};
}

std::shared_ptr<fizz::SelfCert> readCert() {
	auto certificate = fizz::test::getCert(fizz::test::kP256Certificate);
	auto privKey = fizz::test::getPrivateKey(fizz::test::kP256Key);
	std::vector<folly::ssl::X509UniquePtr> certs;
	certs.emplace_back(std::move(certificate));
	return std::make_shared<fizz::SelfCertImpl<fizz::KeyType::P256>>(
	std::move(privKey), std::move(certs));
}

void Ciphers::createServerCtx() {
	auto cert = readCert();
	auto certManager = std::make_unique<fizz::server::CertManager>();
	certManager->addCert(std::move(cert), true);
	auto serverCtx = std::make_shared<fizz::server::FizzServerContext>();
	serverCtx->setFactory(std::make_shared<QuicFizzFactory>());
	serverCtx->setCertManager(std::move(certManager));
	serverCtx->setOmitEarlyRecordLayer(true);
	serverCtx->setClock(std::make_shared<fizz::SystemClock>());
	serverCtx->setFactory(cryptoFactory_.getFizzFactory());
	serverCtx->setSupportedCiphers({{fizz::CipherSuite::TLS_AES_128_GCM_SHA256}});
	serverCtx->setVersionFallbackEnabled(false);
	// Since Draft-17, client won't sent EOED
	serverCtx->setOmitEarlyRecordLayer(true);
	state_.context() = std::move(serverCtx);
}

Ciphers::Ciphers() {
	createServerCtx();
}

void Ciphers::computeCiphers(
	folly::ByteRange secret,
	uint64_t aeadHashIndex,
	uint64_t headerCipherHashIndex) {
	std::unique_ptr<quic::Aead> aead;
	std::unique_ptr<quic::PacketNumberCipher> headerCipher;
	std::tie(aead, headerCipher) = buildCiphers(secret);
	aeadCiphers[aeadHashIndex] = std::move(aead);
	headerCiphers[headerCipherHashIndex] = std::move(headerCipher);
}

void Ciphers::inplaceEncrypt(
	uint64_t aeadHashIndex,
	uint64_t packetNum,
	void *header,
	size_t headerLen,
	void *body,
	size_t bodyLen) {
	std::unique_ptr<folly::IOBuf> plaintext = folly::IOBuf::wrapBuffer(body, bodyLen);
	std::unique_ptr<folly::IOBuf> associatedData = folly::IOBuf::wrapBuffer(header, headerLen);
	plaintext->trimEnd(aeadCiphers.at(aeadHashIndex)->getCipherOverhead());
	aeadCiphers.at(aeadHashIndex)->inplaceEncrypt(
		std::move(plaintext), associatedData.get(), packetNum);
}

void Ciphers::encryptPacketHeader(
	uint64_t headerCipherIndex,
	HeaderForm headerForm,
	uint8_t *header,
	size_t headerLen,
	uint8_t *body,
	size_t bodyLen) {
	// Header encryption.
	auto packetNumberLength = parsePacketNumberLength(*header);
	Sample sample;
	size_t sampleBytesToUse = kMaxPacketNumEncodingSize - packetNumberLength;
	// If there were less than 4 bytes in the packet number, some of the payload
	// bytes will also be skipped during sampling.
	CHECK_GE(bodyLen, sampleBytesToUse + sample.size());
	body += sampleBytesToUse;
	memcpy(sample.data(), body, sample.size());

	folly::MutableByteRange initialByteRange(static_cast<uint8_t *>(header), 1);
	folly::MutableByteRange packetNumByteRange(
		header + headerLen - packetNumberLength, packetNumberLength);
	if (headerForm == HeaderForm::Short) {
		headerCiphers.at(headerCipherIndex)->encryptShortHeader(
			sample, initialByteRange, packetNumByteRange);
	} else {
		headerCiphers.at(headerCipherIndex)->encryptLongHeader(
			sample, initialByteRange, packetNumByteRange);
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
