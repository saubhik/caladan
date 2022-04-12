#pragma once

#include <fizz/protocol/OpenSSLFactory.h>

#include "Aead.h"
#include "PacketNumberCipher.h"

namespace quic {

using Buf = std::unique_ptr<folly::IOBuf>;

// max size of a connId as specified in the draft
constexpr size_t kMaxConnectionIdSize = 20;

#if 0
struct ConnectionId {
	uint8_t *data();

	const uint8_t *data() const;

	uint8_t size() const;

	explicit ConnectionId(const std::vector<uint8_t> &connidIn);

	explicit ConnectionId(folly::io::Cursor &cursor, size_t len);

	bool operator==(const ConnectionId &other) const;

	bool operator!=(const ConnectionId &other) const;

	std::string hex() const;

	/**
	 * Create an connection without any checks for tests.
	 */
	static ConnectionId createWithoutChecks(const std::vector<uint8_t> &connidIn);

	/**
	 * Create a random ConnectionId with the given length.
	 */
	static ConnectionId createRandom(size_t len);

 private:
	ConnectionId() = default;

	std::array<uint8_t, kMaxConnectionIdSize> connid;
	uint8_t connidLen;
};

enum class QuicVersion : uint32_t {
	VERSION_NEGOTIATION = 0x00000000,
	MVFST_D24 = 0xfaceb001,
	// Before updating the MVFST version, please check
	// QuicTransportBase::isKnobSupported() and make sure that knob support is not
	// broken.
	MVFST = 0xfaceb002,
	QUIC_DRAFT_LEGACY = 0xff00001b, // Draft-27
	QUIC_DRAFT = 0xff00001d, // Draft-29
	MVFST_EXPERIMENTAL = 0xfaceb00e, // Experimental alias for MVFST
	MVFST_INVALID = 0xfaceb00f,
};

constexpr folly::StringPiece kQuicKeyLabel = "quic key";
constexpr folly::StringPiece kQuicIVLabel = "quic iv";
constexpr folly::StringPiece kQuicPNLabel = "quic hp";
constexpr folly::StringPiece kClientInitialLabel = "client in";
constexpr folly::StringPiece kServerInitialLabel = "server in";
constexpr folly::StringPiece kQuicDraft22Salt =
	"\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a";
constexpr folly::StringPiece kQuicDraft23Salt =
	"\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";
constexpr folly::StringPiece kQuicDraft29Salt =
	"\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99";

class CryptoFactory {
 public:
	std::unique_ptr<Aead> getClientInitialCipher(
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const;

	std::unique_ptr<Aead> getServerInitialCipher(
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const;

	Buf
	makeServerInitialTrafficSecret(
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const;

	Buf
	makeClientInitialTrafficSecret(
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const;

	/**
	 * Makes the header cipher for writing client initial packets.
	 */
	std::unique_ptr<PacketNumberCipher> makeClientInitialHeaderCipher(
		const ConnectionId
		&initialDestinationConnectionId,
		QuicVersion
		version) const;

	/**
	 * Makes the header cipher for writing server initial packets.
	 */
	std::unique_ptr<PacketNumberCipher> makeServerInitialHeaderCipher(
		const ConnectionId
		&initialDestinationConnectionId,
		QuicVersion
		version) const;

	/**
	 * Crypto layer specifc methods.
	 */
	virtual
	Buf
	makeInitialTrafficSecret(
		folly::StringPiece
		label,
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const = 0;

	virtual
	std::unique_ptr<Aead> makeInitialAead(
		folly::StringPiece
		label,
		const ConnectionId
		&clientDestinationConnId,
		QuicVersion
		version) const = 0;

	virtual
	std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
		folly::ByteRange
		baseSecret) const = 0;

	virtual
	~CryptoFactory() =
	default;
};

class QuicFizzFactory : public fizz::OpenSSLFactory {
	std::unique_ptr<fizz::PlaintextReadRecordLayer> makePlaintextReadRecordLayer()
	const override;

	std::unique_ptr<fizz::PlaintextWriteRecordLayer>
	makePlaintextWriteRecordLayer() const override;

	std::unique_ptr<fizz::EncryptedReadRecordLayer> makeEncryptedReadRecordLayer(
		fizz::EncryptionLevel encryptionLevel) const override;

	std::unique_ptr<fizz::EncryptedWriteRecordLayer>
	makeEncryptedWriteRecordLayer(
		fizz::EncryptionLevel encryptionLevel) const override;
};

class FizzCryptoFactory : public CryptoFactory {
 public:
	FizzCryptoFactory() : fizzFactory_{std::make_shared<QuicFizzFactory>()} {}

	Buf makeInitialTrafficSecret(
		folly::StringPiece label,
		const ConnectionId& clientDestinationConnId,
		QuicVersion version) const override;

	std::unique_ptr<Aead> makeInitialAead(
		folly::StringPiece label,
		const ConnectionId& clientDestinationConnId,
		QuicVersion version) const override;

	std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
		folly::ByteRange baseSecret) const override;

	virtual std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
		fizz::CipherSuite cipher) const;

	std::shared_ptr<fizz::Factory> getFizzFactory() {
		return fizzFactory_;
	}

 protected:
	std::shared_ptr<QuicFizzFactory> fizzFactory_;
};
#endif

} // namespace quic
