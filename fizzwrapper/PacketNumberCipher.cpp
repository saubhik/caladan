#include "PacketNumberCipher.h"

namespace quic {

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

size_t parsePacketNumberLength(uint8_t initialByte) {
	static_assert(
		LongHeader::kPacketNumLenMask == ShortHeader::kPacketNumLenMask,
		"Expected both pn masks are the same");
	return (initialByte & LongHeader::kPacketNumLenMask) + 1;
}

void PacketNumberCipher::decipherHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes,
	uint8_t initialByteMask,
	uint8_t /* packetNumLengthMask */) const {
	CHECK_EQ(packetNumberBytes.size(), kMaxPacketNumEncodingSize);
	HeaderProtectionMask headerMask = mask(sample);
	// Mask size should be > packet number length + 1.
	DCHECK_GE(headerMask.size(), 5);
	initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
	size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
	for (size_t i = 0; i < packetNumLength; ++i) {
		packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
	}
}

void PacketNumberCipher::cipherHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes,
	uint8_t initialByteMask,
	uint8_t /* packetNumLengthMask */) const {
	HeaderProtectionMask headerMask = mask(sample);
	// Mask size should be > packet number length + 1.
	DCHECK_GE(headerMask.size(), kMaxPacketNumEncodingSize + 1);
	size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
	initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
	for (size_t i = 0; i < packetNumLength; ++i) {
		packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
	}
}

void PacketNumberCipher::decryptLongHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes) const {
	decipherHeader(
		sample,
		initialByte,
		packetNumberBytes,
		LongHeader::kTypeBitsMask,
		LongHeader::kPacketNumLenMask);
}

void PacketNumberCipher::decryptShortHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes) const {
	decipherHeader(
		sample,
		initialByte,
		packetNumberBytes,
		ShortHeader::kTypeBitsMask,
		ShortHeader::kPacketNumLenMask);
}

void PacketNumberCipher::encryptLongHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes) const {
	cipherHeader(
		sample,
		initialByte,
		packetNumberBytes,
		LongHeader::kTypeBitsMask,
		LongHeader::kPacketNumLenMask);
}

void PacketNumberCipher::encryptShortHeader(
	folly::ByteRange sample,
	folly::MutableByteRange initialByte,
	folly::MutableByteRange packetNumberBytes) const {
	cipherHeader(
		sample,
		initialByte,
		packetNumberBytes,
		ShortHeader::kTypeBitsMask,
		ShortHeader::kPacketNumLenMask);
}

static void setKeyImpl(
	folly::ssl::EvpCipherCtxUniquePtr &context,
	const EVP_CIPHER *cipher,
	folly::ByteRange key) {
	DCHECK_EQ(key.size(), EVP_CIPHER_key_length(cipher));
	context.reset(EVP_CIPHER_CTX_new());
	if (context == nullptr) {
		throw std::runtime_error("Unable to allocate an EVP_CIPHER_CTX object");
	}
	if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, key.data(), nullptr) !=
	    1) {
		throw std::runtime_error("Init error");
	}
}

static HeaderProtectionMask maskImpl(
	const folly::ssl::EvpCipherCtxUniquePtr &context,
	folly::ByteRange sample) {
	HeaderProtectionMask outMask;
	CHECK_EQ(sample.size(), outMask.size());
	int outLen = 0;
	if (EVP_EncryptUpdate(
		context.get(),
		outMask.data(),
		&outLen,
		sample.data(),
		sample.size()) != 1 ||
	    static_cast<HeaderProtectionMask::size_type>(outLen) != outMask.size()) {
		throw std::runtime_error("Encryption error");
	}
	return outMask;
}

void Aes128PacketNumberCipher::setKey(folly::ByteRange key) {
	return setKeyImpl(encryptCtx_, EVP_aes_128_ecb(), key);
}

void Aes256PacketNumberCipher::setKey(folly::ByteRange key) {
	return setKeyImpl(encryptCtx_, EVP_aes_256_ecb(), key);
}

HeaderProtectionMask Aes128PacketNumberCipher::mask(
	folly::ByteRange sample) const {
	return maskImpl(encryptCtx_, sample);
}

HeaderProtectionMask Aes256PacketNumberCipher::mask(
	folly::ByteRange sample) const {
	return maskImpl(encryptCtx_, sample);
}

constexpr size_t kAES128KeyLength = 16;

size_t Aes128PacketNumberCipher::keyLength() const {
	return kAES128KeyLength;
}

constexpr size_t kAES256KeyLength = 32;

size_t Aes256PacketNumberCipher::keyLength() const {
	return kAES256KeyLength;
}

} // namespace quic
