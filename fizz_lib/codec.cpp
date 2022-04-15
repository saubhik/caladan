#include <string>
#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/AESGCM256.h>
#include <fizz/crypto/aead/AESOCB128.h>
#include <fizz/crypto/aead/ChaCha20Poly1305.h>
#include <fizz/crypto/aead/IOBufUtil.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>
#include <fizz/record/Types.h>
#include <folly/ExceptionWrapper.h>
#include <folly/String.h>
#include <quic/QuicConstants.h>
#include <quic/codec/QuicReadCodec.h>
#include <folly/io/Cursor.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>


#include <list>
#include <stdexcept>
#include <iostream>

#include "codec.h"


MyCipher::MyCipher(std::string key, std::string iv) {
  TrafficKey trafficKey;
  cipher = OpenSSLEVPCipher::makeCipher<AESGCM128>();
	trafficKey.key = IOBuf::copyBuffer(key);
	trafficKey.iv = IOBuf::copyBuffer(iv);
  cipher->setKey(std::move(trafficKey));
}

MyCipher::~MyCipher() {}

void dummyfree(void *ptr, void *userdata) {}

// Expect that data buffer = (payload, tail), with last "overhead" bytes free
void *MyCipher::encrypt(void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo) {
  std::unique_ptr<IOBuf> plaintext = IOBuf::takeOwnership(payload, payload_and_tail, dummyfree);
  std::unique_ptr<IOBuf> aadbuf = IOBuf::takeOwnership(aad, aadlen, dummyfree);
  plaintext->trimEnd(cipher->getCipherOverhead());
  auto ciphertext = cipher->inplaceEncrypt(std::move(plaintext), aadbuf.get(), seqNo);
  return (void *)std::move(ciphertext).get();
}

void *MyCipher::decrypt(void *payload, void *aad, int payload_and_tail, int aadlen, uint64_t seqNo) {
  std::unique_ptr<IOBuf> ciphertext = IOBuf::takeOwnership(payload, payload_and_tail, dummyfree);
  std::unique_ptr<IOBuf> aadbuf = IOBuf::takeOwnership(aad, aadlen, dummyfree);
  auto decrypted = cipher->decrypt(std::move(ciphertext), aadbuf.get(), seqNo);
  return (void *)std::move(decrypted).get();
}


uint32_t tryParseHeader(void *header, int udplen) {
  std::unique_ptr<IOBuf> data = IOBuf::takeOwnership(header, udplen, dummyfree);
  folly::io::Cursor cursor(data.get());
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return std::numeric_limits<uint32_t>::max();
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  auto headerForm = quic::getHeaderForm(initialByte);
  if (headerForm == quic::HeaderForm::Long) {
    return std::numeric_limits<uint32_t>::max();
  } else if (initialByte & quic::ShortHeader::kFixedBitMask) {
    // Assumption:
    // constexpr size_t kDefaultConnectionIdSize = 8;
    return 1;
  }
  return 0;
}