#include "Aead.h"

namespace quic {

EncryptionLevel getEncryptionLevelFromFizz(
	const fizz::EncryptionLevel encryptionLevel) {
	switch (encryptionLevel) {
		case fizz::EncryptionLevel::Plaintext:
			return EncryptionLevel::Initial;
		case fizz::EncryptionLevel::Handshake:
			return EncryptionLevel::Handshake;
		case fizz::EncryptionLevel::EarlyData:
			return EncryptionLevel::EarlyData;
		case fizz::EncryptionLevel::AppTraffic:
			return EncryptionLevel::AppData;
	}

	folly::assume_unreachable();
}

} // namespace quic
