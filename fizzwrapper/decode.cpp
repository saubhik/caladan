#include "decode.h"

#include <fizz/protocol/Protocol.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

CodecResult ReadCodecCiphers::parseLongHeaderPacket(BufQueue &queue)
{
	folly::io::Cursor cursor(queue.front());
	auto initialByte = cursor.readBE<uint8_t>();
	auto longHeaderInvariant = parseLongHeaderInvariant(initialByte, cursor);
	if (!longHeaderInvariant) {
		VLOG(0) << "Dropping packet, failed to parse invariant";
		// We've failed to parse the long header, so we have no idea where this
		// packet ends. Clear the queue since no other data in this packet is
		// parse-able.
		queue.move();
		return CodecResult(Nothing());
	}
	if (longHeaderInvariant->invariant.version ==
		QuicVersion::VERSION_NEGOTIATION) {
		// We shouldn't handle VN packets while parsing the long header.
		// We assume here that they have been handled before calling this
		// function.
		// Since VN is not allowed to be coalesced with another packet
		// type, we clear out the buffer to avoid anyone else parsing it.
		queue.move();
		return CodecResult(Nothing());
	}
	auto type = parseLongHeaderType(initialByte);

	auto parsedLongHeader = parseLongHeaderVariants(
		type, std::move(*longHeaderInvariant), cursor, nodeType_);
	if (!parsedLongHeader) {
		VLOG(0) << "Dropping due to failed to parse header";
		// We've failed to parse the long header, so we have no idea where this
		// packet ends. Clear the queue since no other data in this packet is
		// parse-able.
		queue.move();
		return CodecResult(Nothing());
	}
	// As soon as we have parsed out the long header we can split off any
	// coalesced packets. We do this early since the spec mandates that decryption
	// failure must not stop the processing of subsequent coalesced packets.
	auto longHeader = std::move(parsedLongHeader->header);

	if (type == LongHeader::Types::Retry) {
		queue.move();
		return CodecResult(Nothing());
	}

	uint64_t packetNumberOffset = cursor.getCurrentPosition();
	size_t currentPacketLen =
		packetNumberOffset + parsedLongHeader->packetLength.packetLength;
	if (queue.chainLength() < currentPacketLen) {
		// Packet appears truncated, there's no parse-able data left.
		queue.move();
		return CodecResult(Nothing());
	}
	auto currentPacketData = queue.splitAtMost(currentPacketLen);
	cursor.reset(currentPacketData.get());
	cursor.skip(packetNumberOffset);
	// Sample starts after the max packet number size. This ensures that we
	// have enough bytes to skip before we can start reading the sample.
	if (!cursor.canAdvance(kMaxPacketNumEncodingSize)) {
		VLOG(0) << "Dropping packet, not enough for packet number";
		// Packet appears truncated, there's no parse-able data left.
		queue.move();
		return CodecResult(Nothing());
	}
	cursor.skip(kMaxPacketNumEncodingSize);
	Sample sample;
	if (!cursor.canAdvance(sample.size())) {
		VLOG(0) << "Dropping packet, sample too small";
		// Packet appears truncated, there's no parse-able data left.
		queue.move();
		return CodecResult(Nothing());
	}
	cursor.pull(sample.data(), sample.size());

	const PacketNumberCipher *headerCipher{nullptr};
	const Aead *cipher{nullptr};
	auto protectionType = longHeader.getProtectionType();
	switch (protectionType) {
	case ProtectionType::Initial:
		if (!initialHeaderCipher_) {
			VLOG(0) << nodeToString(nodeType_)
				<< " dropping initial packet after initial keys dropped";
			return CodecResult(Nothing());
		}
		headerCipher = initialHeaderCipher_.get();
		cipher = initialReadCipher_.get();
		break;
	case ProtectionType::Handshake:
		headerCipher = handshakeHeaderCipher_.get();
		cipher = handshakeReadCipher_.get();
		break;
	case ProtectionType::ZeroRtt:
		headerCipher = zeroRttHeaderCipher_.get();
		cipher = zeroRttReadCipher_.get();
		break;
	case ProtectionType::KeyPhaseZero:
	case ProtectionType::KeyPhaseOne:
		CHECK(false) << "one rtt protection type in long header";
	}
	if (!headerCipher || !cipher) {
		return CodecResult(
			CipherUnavailable(std::move(currentPacketData), 0, protectionType));
	}

	PacketNum expectedNextPacketNum = 0;
	folly::Optional<PacketNum> largestReceivedPacketNum;
	switch (longHeaderTypeToProtectionType(type)) {
	case ProtectionType::Initial:
		largestReceivedPacketNum =
			ackStates.initialAckState.largestReceivedPacketNum;
		break;
	case ProtectionType::Handshake:
		largestReceivedPacketNum =
			ackStates.handshakeAckState.largestReceivedPacketNum;
		break;
	case ProtectionType::ZeroRtt:
		largestReceivedPacketNum =
			ackStates.appDataAckState.largestReceivedPacketNum;
		break;
	default:
		folly::assume_unreachable();
	}
	if (largestReceivedPacketNum) {
		expectedNextPacketNum = 1 + *largestReceivedPacketNum;
	}
	folly::MutableByteRange initialByteRange(currentPacketData->writableData(),
		1);
	folly::MutableByteRange packetNumberByteRange(
		currentPacketData->writableData() + packetNumberOffset,
		kMaxPacketNumEncodingSize);
	headerCipher->decryptLongHeader(folly::range(sample), initialByteRange,
		packetNumberByteRange);
	std::pair<PacketNum, size_t> packetNum = parsePacketNumber(
		initialByteRange.data()[0], packetNumberByteRange, expectedNextPacketNum);

	longHeader.setPacketNumber(packetNum.first);
	BufQueue decryptQueue;
	decryptQueue.append(std::move(currentPacketData));
	size_t aadLen = packetNumberOffset + packetNum.second;
	auto headerData = decryptQueue.splitAtMost(aadLen);
	// parsing verifies that packetLength >= packet number length.
	auto encryptedData = decryptQueue.splitAtMost(
		parsedLongHeader->packetLength.packetLength - packetNum.second);
	if (!encryptedData) {
		// There should normally be some integrity tag at least in the data,
		// however allowing the aead to process the data even if the tag is not
		// present helps with writing tests.
		encryptedData = folly::IOBuf::create(0);
	}

	auto decryptAttempt = cipher->tryDecrypt(std::move(encryptedData),
		headerData.get(), packetNum.first);
	if (!decryptAttempt) {
		VLOG(0) << "Unable to decrypt packet=" << packetNum.first
			<< " packetNumLen=" << parsePacketNumberLength(initialByte)
			<< " protectionType=" << toString(protectionType);
		return CodecResult(Nothing());
	}

	// @saubhik: No need to parse frames.
	return RegularQuicPacket(std::move(longHeader));
}

CodecResult ReadCodecCiphers::tryParseShortHeaderPacket(
	Buf data, size_t dstConnIdSize, folly::io::Cursor &cursor)
{
	size_t packetNumberOffset = 1 + dstConnIdSize;
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
		parseShortHeader(initialByteRange.data()[0], cursor, dstConnIdSize);
	if (!shortHeader) {
		VLOG(0) << "Dropping packet, cannot parse";
		return CodecResult(Nothing());
	}

	shortHeader->setPacketNumber(packetNum.first);
	if (shortHeader->getProtectionType() == ProtectionType::KeyPhaseOne) {
		VLOG(0) << nodeToString(nodeType_) << " cannot read key phase one packet";
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

	// @saubhik: We do not need to parse frames.
	return RegularQuicPacket(std::move(*shortHeader));
}

CodecResult ReadCodecCiphers::parsePacket(BufQueue &queue,
	size_t dstConnIdSize)
{
	if (queue.empty()) {
		return CodecResult(Nothing());
	}
	DCHECK(!queue.front()->isChained());
	folly::io::Cursor cursor(queue.front());
	if (!cursor.canAdvance(sizeof(uint8_t))) {
		return CodecResult(Nothing());
	}
	uint8_t initialByte = cursor.readBE<uint8_t>();
	auto headerForm = getHeaderForm(initialByte);
	if (headerForm == HeaderForm::Long) {
		return parseLongHeaderPacket(queue);
	}

	// Missing 1-rtt Cipher is the only case we wouldn't consider reset
	// TODO: support key phase one.
	if (!oneRttReadCipher_ || !oneRttHeaderCipher_) {
		VLOG(0) << nodeToString(nodeType_) << " cannot read key phase zero packet";
		VLOG(0) << "cannot read data="
			<< folly::hexlify(queue.front()->clone()->moveToFbString());
		return CodecResult(
			CipherUnavailable(queue.move(), 0, ProtectionType::KeyPhaseZero));
	}

	auto data = queue.move();
	auto maybeShortHeaderPacket =
		tryParseShortHeaderPacket(std::move(data), dstConnIdSize, cursor);
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

void ReadCodecCiphers::processPacketData(BufQueue &packetQueue)
{
	auto packetSize = packetQueue.chainLength();
	if (packetSize == 0) {
		return;
	}

	auto parsedPacket = parsePacket(packetQueue, 0);
	RegularQuicPacket *regularOptional = parsedPacket.regularPacket();
	if (!regularOptional) {
		return;
	}

	auto packetNum = regularOptional->header.getPacketSequenceNum();
	auto pnSpace = regularOptional->header.getPacketNumberSpace();

	auto &ackState = getAckState(pnSpace);
	updateLargestReceivedPacketNum(ackState, packetNum);
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

void ReadCodecCiphers::decrypt(void *data, size_t dataLen)
{
	BufQueue udpData;
	udpData.append(std::move(folly::IOBuf::wrapBuffer(data, dataLen)));
	for (uint16_t processedPackets = 0;
		!udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
		processedPackets++) {
		processPacketData(udpData);
	}
	VLOG_IF(0, !udpData.empty()) << "Leaving " << udpData.chainLength()
		<< " bytes unprocessed after attempting to process "
		<< kMaxNumCoalescedPackets << " packets.";
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
