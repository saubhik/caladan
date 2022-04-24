#pragma once

#include <folly/Optional.h>
#include <folly/io/Cursor.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

namespace quic {

enum class HeaderForm : bool {
	Long = 1,
	Short = 0,
};

constexpr auto kMaxPacketNumEncodingSize = 4;

struct LongHeader {
	static constexpr uint8_t kFixedBitMask = 0x40;
	static constexpr uint8_t kPacketTypeMask = 0x30;
	static constexpr uint8_t kReservedBitsMask = 0x0c;
	static constexpr uint8_t kPacketNumLenMask = 0x03;
	static constexpr uint8_t kTypeBitsMask = 0x0F;
};

struct ShortHeader {
	// There is also a spin bit which is 0x20 that we don't currently implement.
	static constexpr uint8_t kFixedBitMask = 0x40;
	static constexpr uint8_t kReservedBitsMask = 0x18;
	static constexpr uint8_t kKeyPhaseMask = 0x04;
	static constexpr uint8_t kPacketNumLenMask = 0x03;
	static constexpr uint8_t kTypeBitsMask = 0x1F;
};

size_t parsePacketNumberLength(uint8_t initialByte);

using HeaderProtectionMask = std::array<uint8_t, 16>;
using Sample = std::array<uint8_t, 16>;

class PacketNumberCipher {
 public:
	virtual ~PacketNumberCipher() = default;

	virtual void setKey(folly::ByteRange key) = 0;

	virtual HeaderProtectionMask mask(folly::ByteRange sample) const = 0;

	/**
	 * Decrypts a long header from a sample.
	 * sample should be 16 bytes long.
	 * initialByte is the initial byte.
	 * packetNumberBytes should be supplied with at least 4 bytes.
	 */
	virtual void decryptLongHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes) const;

	/**
	 * Decrypts a short header from a sample.
	 * sample should be 16 bytes long.
	 * initialByte is the initial byte.
	 * packetNumberBytes should be supplied with at least 4 bytes.
	 */
	virtual void decryptShortHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes) const;

	/**
	 * Encrypts a long header from a sample.
	 * sample should be 16 bytes long.
	 * initialByte is the initial byte.
	 */
	virtual void encryptLongHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes) const;

	/**
	 * Encrypts a short header from a sample.
	 * sample should be 16 bytes long.
	 * initialByte is the initial byte.
	 */
	virtual void encryptShortHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes) const;

	/**
	 * Returns the length of key needed for the pn cipher.
	 */
	virtual size_t keyLength() const = 0;

 protected:
	virtual void cipherHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes,
		uint8_t initialByteMask,
		uint8_t packetNumLengthMask) const;

	virtual void decipherHeader(
		folly::ByteRange sample,
		folly::MutableByteRange initialByte,
		folly::MutableByteRange packetNumberBytes,
		uint8_t initialByteMask,
		uint8_t packetNumLengthMask) const;
};

class Aes128PacketNumberCipher : public PacketNumberCipher {
 public:
	~Aes128PacketNumberCipher() override = default;

	void setKey(folly::ByteRange key) override;

	HeaderProtectionMask mask(folly::ByteRange sample) const override;

	size_t keyLength() const override;

 private:
	folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;
};

class Aes256PacketNumberCipher : public PacketNumberCipher {
 public:
	~Aes256PacketNumberCipher() override = default;

	void setKey(folly::ByteRange key) override;

	HeaderProtectionMask mask(folly::ByteRange sample) const override;

	size_t keyLength() const override;

 private:
	folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;
};

} // namespace quic
