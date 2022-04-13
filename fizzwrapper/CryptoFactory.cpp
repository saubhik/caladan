#include "CryptoFactory.h"

namespace {

class QuicPlaintextReadRecordLayer : public fizz::PlaintextReadRecordLayer {
 public:
	~QuicPlaintextReadRecordLayer() override = default;

	folly::Optional<fizz::TLSMessage> read(folly::IOBufQueue &buf) override {
		if (buf.empty()) {
			return folly::none;
		}
		fizz::TLSMessage msg;
		msg.type = fizz::ContentType::handshake;
		msg.fragment = buf.move();
		return msg;
	}
};

class QuicEncryptedReadRecordLayer : public fizz::EncryptedReadRecordLayer {
 public:
	~QuicEncryptedReadRecordLayer() override = default;

	explicit QuicEncryptedReadRecordLayer(fizz::EncryptionLevel encryptionLevel)
		: fizz::EncryptedReadRecordLayer(encryptionLevel) {}

	folly::Optional<fizz::TLSMessage> read(folly::IOBufQueue &buf) override {
		if (buf.empty()) {
			return folly::none;
		}
		fizz::TLSMessage msg;
		msg.type = fizz::ContentType::handshake;
		msg.fragment = buf.move();
		return msg;
	}
};

class QuicPlaintextWriteRecordLayer : public fizz::PlaintextWriteRecordLayer {
 public:
	~QuicPlaintextWriteRecordLayer() override = default;

	fizz::TLSContent write(fizz::TLSMessage &&msg) const override {
		fizz::TLSContent content;
		content.data = std::move(msg.fragment);
		content.contentType = msg.type;
		content.encryptionLevel = getEncryptionLevel();
		return content;
	}

	fizz::TLSContent writeInitialClientHello(
		std::unique_ptr<folly::IOBuf> encodedClientHello) const override {
		return write(fizz::TLSMessage{
			fizz::ContentType::handshake, std::move(encodedClientHello)});
	}
};

class QuicEncryptedWriteRecordLayer : public fizz::EncryptedWriteRecordLayer {
 public:
	~QuicEncryptedWriteRecordLayer() override = default;

	explicit QuicEncryptedWriteRecordLayer(fizz::EncryptionLevel encryptionLevel)
		: EncryptedWriteRecordLayer(encryptionLevel) {}

	fizz::TLSContent write(fizz::TLSMessage &&msg) const override {
		fizz::TLSContent content;
		content.data = std::move(msg.fragment);
		content.contentType = msg.type;
		content.encryptionLevel = getEncryptionLevel();
		return content;
	}
};

} // namespace

namespace quic {

uint8_t* ConnectionId::data() {
	return connid.data();
}

const uint8_t* ConnectionId::data() const {
	return connid.data();
}

uint8_t ConnectionId::size() const {
	return connidLen;
}

std::unique_ptr<Aead> CryptoFactory::getClientInitialCipher(
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	return makeInitialAead(kClientInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<Aead> CryptoFactory::getServerInitialCipher(
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	return makeInitialAead(kServerInitialLabel, clientDestinationConnId, version);
}

Buf CryptoFactory::makeServerInitialTrafficSecret(
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	return makeInitialTrafficSecret(
		kServerInitialLabel, clientDestinationConnId, version);
}

Buf CryptoFactory::makeClientInitialTrafficSecret(
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	return makeInitialTrafficSecret(
		kClientInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<PacketNumberCipher>
CryptoFactory::makeClientInitialHeaderCipher(
	const ConnectionId &initialDestinationConnectionId,
	QuicVersion version) const {
	auto clientInitialTrafficSecret =
		makeClientInitialTrafficSecret(initialDestinationConnectionId, version);
	return makePacketNumberCipher(clientInitialTrafficSecret->coalesce());
}

std::unique_ptr<PacketNumberCipher>
CryptoFactory::makeServerInitialHeaderCipher(
	const ConnectionId &initialDestinationConnectionId,
	QuicVersion version) const {
	auto serverInitialTrafficSecret =
		makeServerInitialTrafficSecret(initialDestinationConnectionId, version);
	return makePacketNumberCipher(serverInitialTrafficSecret->coalesce());
}

std::unique_ptr<fizz::PlaintextReadRecordLayer>
QuicFizzFactory::makePlaintextReadRecordLayer() const {
	return std::make_unique<QuicPlaintextReadRecordLayer>();
}

std::unique_ptr<fizz::PlaintextWriteRecordLayer>
QuicFizzFactory::makePlaintextWriteRecordLayer() const {
	return std::make_unique<QuicPlaintextWriteRecordLayer>();
}

std::unique_ptr<fizz::EncryptedReadRecordLayer>
QuicFizzFactory::makeEncryptedReadRecordLayer(
	fizz::EncryptionLevel encryptionLevel) const {
	return std::make_unique<QuicEncryptedReadRecordLayer>(encryptionLevel);
}

std::unique_ptr<fizz::EncryptedWriteRecordLayer>
QuicFizzFactory::makeEncryptedWriteRecordLayer(
	fizz::EncryptionLevel encryptionLevel) const {
	return std::make_unique<QuicEncryptedWriteRecordLayer>(encryptionLevel);
}

Buf FizzCryptoFactory::makeInitialTrafficSecret(
	folly::StringPiece label,
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	auto deriver =
		fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
	auto connIdRange = folly::range(clientDestinationConnId);
	folly::StringPiece salt;
	switch (version) {
		// Our transport version is equivalent to d-24 mostly, but we never
		// updated the salt to avoid a version transition.
		case QuicVersion::MVFST_D24:
			salt = kQuicDraft22Salt;
			break;
		case QuicVersion::QUIC_DRAFT:
			salt = kQuicDraft29Salt;
			break;
		case QuicVersion::QUIC_DRAFT_LEGACY:
		case QuicVersion::MVFST:
			salt = kQuicDraft23Salt;
			break;
		default:
			// Default to one arbitrarily.
			salt = kQuicDraft23Salt;
	}
	auto initialSecret = deriver->hkdfExtract(salt, connIdRange);
	auto trafficSecret = deriver->expandLabel(
		folly::range(initialSecret),
		label,
		folly::IOBuf::create(0),
		fizz::Sha256::HashLen);
	return trafficSecret;
}

std::unique_ptr<Aead> FizzCryptoFactory::makeInitialAead(
	folly::StringPiece label,
	const ConnectionId &clientDestinationConnId,
	QuicVersion version) const {
	auto trafficSecret =
		makeInitialTrafficSecret(label, clientDestinationConnId, version);
	auto deriver =
		fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
	auto aead = fizzFactory_->makeAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
	auto key = deriver->expandLabel(
		trafficSecret->coalesce(),
		kQuicKeyLabel,
		folly::IOBuf::create(0),
		aead->keyLength());
	auto iv = deriver->expandLabel(
		trafficSecret->coalesce(),
		kQuicIVLabel,
		folly::IOBuf::create(0),
		aead->ivLength());

	fizz::TrafficKey trafficKey = {std::move(key), std::move(iv)};
	aead->setKey(std::move(trafficKey));
	return FizzAead::wrap(std::move(aead));
}

std::unique_ptr<PacketNumberCipher> FizzCryptoFactory::makePacketNumberCipher(
	folly::ByteRange baseSecret) const {
	auto pnCipher =
		makePacketNumberCipher(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
	auto deriver =
		fizzFactory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
	auto pnKey = deriver->expandLabel(
		baseSecret, kQuicPNLabel, folly::IOBuf::create(0), pnCipher->keyLength());
	pnCipher->setKey(pnKey->coalesce());
	return pnCipher;
}

std::unique_ptr<PacketNumberCipher> FizzCryptoFactory::makePacketNumberCipher(
	fizz::CipherSuite cipher) const {
	switch (cipher) {
		case fizz::CipherSuite::TLS_AES_128_GCM_SHA256:
			return std::make_unique<Aes128PacketNumberCipher>();
		case fizz::CipherSuite::TLS_AES_256_GCM_SHA384:
			return std::make_unique<Aes256PacketNumberCipher>();
		default:
			throw std::runtime_error("Packet number cipher not implemented");
	}
}

} // namespace quic
