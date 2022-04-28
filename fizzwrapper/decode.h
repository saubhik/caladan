#pragma once

#include <fizz/client/ClientProtocol.h>
#include <quic/codec/Decode.h>
#include <quic/codec/QuicReadCodec.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/Aead.h>
#include <quic/state/AckStates.h>

namespace quic {

class ReadCodecCiphers {
 public:
	ReadCodecCiphers();
	~ReadCodecCiphers() = default;
	void computeCiphers(void *data, size_t dataLen);
	bool decrypt(void *data, size_t dataLen);

 private:
	fizz::client::State state_;
	FizzCryptoFactory cryptoFactory_;

	enum class CipherKind {
		HandshakeWrite,
		HandshakeRead,
		OneRttWrite,
		OneRttRead,
		ZeroRttWrite,
	};

	// QuicNodeType nodeType_ = QuicNodeType::Client;

	// Cipher used to decrypt handshake packets.
	std::unique_ptr<Aead> initialReadCipher_;

	std::unique_ptr<Aead> oneRttReadCipher_;
	std::unique_ptr<Aead> zeroRttReadCipher_;
	std::unique_ptr<Aead> handshakeReadCipher_;

	std::unique_ptr<PacketNumberCipher> initialHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher_;
	std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher_;

	// This contains the ack and packet number related states for all three
	// packet number space.
	AckStates ackStates;

	bool processPacketData(BufQueue &);
	AckState &getAckState(PacketNumberSpace) noexcept;
	CodecResult parsePacket(BufQueue &, size_t);
	CodecResult tryParseShortHeaderPacket(Buf, size_t, folly::io::Cursor &);
	// CodecResult parseLongHeaderPacket(BufQueue &);
};

} // namespace quic
