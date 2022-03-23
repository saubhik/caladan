#include "codec.h"
#include <iostream>

struct CipherParams {
	std::string key;
	std::string iv;
	uint64_t seqNum;
	std::string aad;
	std::string plaintext;
	std::string ciphertext;
	bool valid;
	//CipherSuite cipher;
};


constexpr size_t kHeadroom = 10;

const CipherParams params = CipherParams{
						"permanantdeaths!",
						"eyeveeRaNdOm",
            1,
            "",
            "01001598234293849238749283740983740928374190283741982",
            "9d4db5ecd768198892531eebac72cf1d477dd0",
            true};
            //CipherSuite::TLS_AES_128_GCM_SHA256};


std::unique_ptr<folly::IOBuf>
toIOBuf(std::string hexData, size_t headroom = 0UL, size_t tailroom = 0UL) {
  std::string out;
  folly::unhexlify(hexData, out);
  return folly::IOBuf::copyBuffer(out, headroom, tailroom);
}

std::unique_ptr<IOBuf> copyBuffer(const folly::IOBuf& buf) {
  std::unique_ptr<IOBuf> out;
  for (auto r : buf) {
    if (out) {
      out->prependChain(IOBuf::copyBuffer(r));
    } else {
      out = IOBuf::copyBuffer(r);
    }
  }
  return out;
}

int main(void) {

	MyCipher cipher(params.key, params.iv);

	char message[26] = "0123456789";
	char aad[] = "";
	char enc_copy[27];

	std::cout << message << "\n";

	cipher.encrypt((void *)message, (void *)aad, 26, 0, params.seqNum);

	memcpy(enc_copy, message, 26); // "send message"
	enc_copy[26] = '\0';

	std::cout << enc_copy << "\n";

	cipher.decrypt((void *)enc_copy, (void *)aad, 26, 0, params.seqNum);

	std::cout << enc_copy << "\n";

	//std::unique_ptr<IOBuf> plaintext = IOBuf::copyBuffer(params.plaintext, kHeadroom, cipher->getCipherOverhead());
	//auto ptcopy = copyBuffer(*plaintext);
	//std::unique_ptr<IOBuf> aad = toIOBuf(params.aad);
	////plaintext->prependChain(IOBuf::create(cipher->getCipherOverhead()));
	//auto inplaceout = cipher->inplaceEncrypt(std::move(plaintext), aad.get(), params.seqNum);
	//auto inplaceoutcopy = copyBuffer(*inplaceout);
	//auto decrypt = cipher->decrypt(std::move(inplaceout), aad.get(), params.seqNum);

	//std::string dec_str((char *)decrypt->data(), decrypt->length());

	//std::cout << "Equal? " << IOBufEqualTo()(ptcopy, decrypt) << "\n";

	//std::cout << params.plaintext << "\n" << dec_str << "\n";

	return 0;
}