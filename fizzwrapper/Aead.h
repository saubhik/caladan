#pragma once

#include <folly/Optional.h>
#include <folly/io/IOBuf.h>

#include <fizz/crypto/aead/Aead.h>
#include <fizz/protocol/Types.h>

namespace quic {

struct TrafficKey {
	std::unique_ptr<folly::IOBuf> key;
	std::unique_ptr<folly::IOBuf> iv;
};

/**
 * Interface for aead algorithms (RFC 5116).
 */
class Aead {
 public:
	virtual ~Aead() = default;

	/**
	 * Encrypts plaintext inplace. Will throw on error.
	 */
	virtual std::unique_ptr<folly::IOBuf> inplaceEncrypt(
		std::unique_ptr<folly::IOBuf> &&plaintext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const = 0;

	/**
	 * Decrypt ciphertext. Will throw if the ciphertext does not decrypt
	 * successfully.
	 */
	virtual std::unique_ptr<folly::IOBuf> decrypt(
		std::unique_ptr<folly::IOBuf> &&ciphertext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const {
		auto plaintext = tryDecrypt(std::move(ciphertext), associatedData, seqNum);
		if (!plaintext) {
			throw std::runtime_error("decryption failed");
		}
		return std::move(*plaintext);
	}

	/**
	 * Decrypt ciphertext. Will return none if the ciphertext does not decrypt
	 * successfully. May still throw from errors unrelated to ciphertext.
	 */
	virtual folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
		std::unique_ptr<folly::IOBuf> &&ciphertext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const = 0;

	/**
	 * Returns the number of bytes the aead will add to the plaintext (size of
	 * ciphertext - size of plaintext).
	 */
	virtual size_t getCipherOverhead() const = 0;
};

/**
* Represent the different encryption levels used by QUIC.
*/
enum class EncryptionLevel : uint8_t {
	Initial,
	Handshake,
	EarlyData,
	AppData,
};

class FizzAead final : public Aead {
 public:
	static std::unique_ptr<FizzAead> wrap(
		std::unique_ptr<fizz::Aead> fizzAeadIn) {
		if (!fizzAeadIn) {
			return nullptr;
		}

		return std::unique_ptr<FizzAead>(new FizzAead(std::move(fizzAeadIn)));
	}

	/**
	 * Simply forward all calls to fizz::Aead.
	 */
	std::unique_ptr<folly::IOBuf> inplaceEncrypt(
		std::unique_ptr<folly::IOBuf> &&plaintext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const override {
		return fizzAead->inplaceEncrypt(std::move(plaintext), associatedData,
		                                seqNum);
	}

	std::unique_ptr<folly::IOBuf> decrypt(
		std::unique_ptr<folly::IOBuf> &&ciphertext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const override {
		return fizzAead->decrypt(std::move(ciphertext), associatedData, seqNum);
	}

	folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
		std::unique_ptr<folly::IOBuf> &&ciphertext,
		const folly::IOBuf *associatedData,
		uint64_t seqNum) const override {
		return fizzAead->tryDecrypt(std::move(ciphertext), associatedData, seqNum);
	}

	size_t getCipherOverhead() const override {
		return fizzAead->getCipherOverhead();
	}

	// For testing.
	const fizz::Aead *getFizzAead() const {
		return fizzAead.get();
	}

 private:
	std::unique_ptr<fizz::Aead> fizzAead;

	explicit FizzAead(std::unique_ptr<fizz::Aead> fizzAeadIn)
		: fizzAead(std::move(fizzAeadIn)) {}
};

EncryptionLevel getEncryptionLevelFromFizz(
	const fizz::EncryptionLevel encryptionLevel);

} // namespace quic
