#include "decode.h"

#include <fizz/protocol/Protocol.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

CodecResult ReadCodecCiphers::tryParseShortHeaderPacket(Buf &data,
	folly::io::Cursor &cursor)
{
	auto dataPtr = data->data();
	size_t packetNumberOffset = 1;
	PacketNum expectedNextPacketNum =
		ackStates.appDataAckState.largestReceivedPacketNum
			? (1 + *ackStates.appDataAckState.largestReceivedPacketNum)
			: 0;
	size_t sampleOffset = packetNumberOffset + kMaxPacketNumEncodingSize;
	Sample sample;
	if (data->computeChainDataLength() < sampleOffset + sample.size()) {
		VLOG(0) << "Dropping packet, too small for sample";
		// There's not enough space for the short header packet
		return CodecResult(Nothing());
	}

	folly::MutableByteRange initialByteRange(data->writableData(), 1);
	folly::MutableByteRange packetNumberByteRange(
		data->writableData() + packetNumberOffset, kMaxPacketNumEncodingSize);
	folly::ByteRange sampleByteRange(data->writableData() + sampleOffset,
		sample.size());

	oneRttHeaderCipher_->decryptShortHeader(sampleByteRange, initialByteRange,
		packetNumberByteRange);
	std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
		initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);
	auto shortHeader =
		parseShortHeader(initialByteRange.data()[0], cursor, 0);
	if (!shortHeader) {
		VLOG(0) << "Dropping packet, cannot parse";
		return CodecResult(Nothing());
	}

	shortHeader->setPacketNumber(packetNum.first);
	if (shortHeader->getProtectionType() == ProtectionType::KeyPhaseOne) {
		VLOG(0) << "Cannot read key phase one packet";
		return CodecResult(Nothing());
	}

	// We know that the iobuf is not chained. This means that we can safely have a
	// non-owning reference to the header without cloning the buffer. If we don't
	// clone the buffer, the buffer will not show up as shared and we can decrypt
	// in-place.
	size_t aadLen = packetNumberOffset + packetNum.second;
	folly::IOBuf headerData =
		folly::IOBuf::wrapBufferAsValue(data->data(), aadLen);
	data->trimStart(aadLen);

	auto decryptAttempt = oneRttReadCipher_->tryDecrypt(
		std::move(data), &headerData, packetNum.first);
	if (!decryptAttempt) {
		auto protectionType = shortHeader->getProtectionType();
		VLOG(0) << "Unable to decrypt packet=" << packetNum.first
			<< " protectionType=" << (int) protectionType;
		return CodecResult(Nothing());
	}

	dataPtr += aadLen;
	memcpy((void *) dataPtr, decryptAttempt.value()->data(),
		decryptAttempt.value()->length());

	// @saubhik: We do not need to parse frames.
	return RegularQuicPacket(std::move(*shortHeader));
}

CodecResult ReadCodecCiphers::parsePacket(Buf &buf)
{
	folly::io::Cursor cursor(buf.get());
	if (!cursor.canAdvance(sizeof(uint8_t))) {
		return CodecResult(Nothing());
	}
	auto initialByte = cursor.readBE<uint8_t>();
	auto headerForm = getHeaderForm(initialByte);
	if (headerForm == HeaderForm::Long) {
		return CodecResult(Nothing());
	}

	// Missing 1-rtt Cipher is the only case we wouldn't consider reset
	// TODO: support key phase one.
	if (!oneRttReadCipher_ || !oneRttHeaderCipher_) {
		VLOG(0) << "Missing oneRtt ciphers";
		VLOG(1) << "cannot read data="
			<< folly::hexlify(buf->clone()->moveToFbString());
		return CodecResult(
			CipherUnavailable(std::move(buf), 0, ProtectionType::KeyPhaseZero));
	}

	auto maybeShortHeaderPacket = tryParseShortHeaderPacket(buf, cursor);
	return maybeShortHeaderPacket;
}

AckState &ReadCodecCiphers::getAckState(PacketNumberSpace pnSpace) noexcept
{
	switch (pnSpace) {
	case PacketNumberSpace::Initial:
		return ackStates.initialAckState;
	case PacketNumberSpace::Handshake:
		return ackStates.handshakeAckState;
	case PacketNumberSpace::AppData:
		return ackStates.appDataAckState;
	}
	folly::assume_unreachable();
}

/**
 * Update largestReceivedPacketNum in ackState with packetNum. Return if the
 * current packetNum is received out of order.
 */
bool updateLargestReceivedPacketNum(AckState &ackState, PacketNum packetNum)
{
	PacketNum expectedNextPacket = 0;
	if (ackState.largestReceivedPacketNum) {
		expectedNextPacket = *ackState.largestReceivedPacketNum + 1;
	}
	ackState.largestReceivedPacketNum = std::max<PacketNum>(
		ackState.largestReceivedPacketNum.value_or(packetNum), packetNum);
	ackState.acks.insert(packetNum);
	return expectedNextPacket != packetNum;
}

bool ReadCodecCiphers::processPacketData(Buf &buf)
{
	auto parsedPacket = parsePacket(buf);
	RegularQuicPacket *regularOptional = parsedPacket.regularPacket();
	if (!regularOptional) {
		return false;
	}
	auto packetNum = regularOptional->header.getPacketSequenceNum();
	auto pnSpace = regularOptional->header.getPacketNumberSpace();
	auto &ackState = getAckState(pnSpace);
	updateLargestReceivedPacketNum(ackState, packetNum);
	return true;
}

void ReadCodecCiphers::computeCiphers(void *data, size_t dataLen)
{
	auto kind = (CipherKind) (*((uint8_t *) data));
	std::vector<uint8_t> secret(dataLen - 1);
	memcpy(&secret[0], (uint8_t *) data + 1, dataLen - 1);

	bool isEarlyTraffic = kind == CipherKind::ZeroRttWrite;
	if (isEarlyTraffic)
		return;

	auto cipher = fizz::CipherSuite::TLS_AES_128_GCM_SHA256;
	auto keyScheduler = (*state_.context()->getFactory()).makeKeyScheduler(
		cipher);
	auto aead = FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
		*state_.context()->getFactory(), *keyScheduler, cipher, secret,
		kQuicKeyLabel, kQuicIVLabel));

	auto packetNumberCipher = cryptoFactory_.makePacketNumberCipher(secret);

	switch (kind) {
	case CipherKind::HandshakeWrite:
		break;
	case CipherKind::HandshakeRead:
		handshakeReadCipher_ = std::move(aead);
		handshakeHeaderCipher_ = std::move(packetNumberCipher);
		break;
	case CipherKind::OneRttWrite:
		break;
	case CipherKind::OneRttRead:
		oneRttReadCipher_ = std::move(aead);
		oneRttHeaderCipher_ = std::move(packetNumberCipher);
		break;
	case CipherKind::ZeroRttWrite:
		break;
	default:
		// Report error?
		break;
	}
}

bool ReadCodecCiphers::decrypt(void *data, size_t dataLen)
{
	auto encrypted = folly::IOBuf::wrapBuffer(data, dataLen);
	return processPacketData(encrypted);
}

class TestCertificateVerifier : public fizz::CertificateVerifier {
 public:
	~TestCertificateVerifier() override = default;

	void verify(const std::vector<std::shared_ptr<const fizz::PeerCert>> &)
	const override
	{
		return;
	}

	std::vector<fizz::Extension> getCertificateRequestExtensions()
	const override
	{
		return std::vector<fizz::Extension>();
	}
};

std::unique_ptr<fizz::CertificateVerifier> createTestCertificateVerifier()
{
	return std::make_unique<TestCertificateVerifier>();
}

ReadCodecCiphers::ReadCodecCiphers()
{
	/* @saubhik: From tperf */
	auto fizzClientContext =
		FizzClientQuicHandshakeContext::Builder()
			.setCertificateVerifier(createTestCertificateVerifier())
			.build();
	/* @saubhik: From FizzClientHandshake::connectImpl() */
	auto context = std::make_shared<fizz::client::FizzClientContext>(
		*fizzClientContext->getContext());
	context->setFactory(cryptoFactory_.getFizzFactory());
	context->setSupportedCiphers({fizz::CipherSuite::TLS_AES_128_GCM_SHA256});
	context->setCompatibilityMode(false);
	// Since Draft-17, EOED should not be sent
	context->setOmitEarlyRecordLayer(true);
	state_.context() = std::move(context);
}

}  // namespace quic
