#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/AESGCM256.h>
#include <fizz/crypto/aead/AESOCB128.h>
#include <fizz/crypto/aead/ChaCha20Poly1305.h>
#include <fizz/crypto/aead/IOBufUtil.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>

using namespace folly;
using namespace fizz;

class MyCipher {
  private:
    std::unique_ptr<Aead> cipher;
  public:
  MyCipher(std::string key, std::string iv);
  ~MyCipher();
  void *encrypt(void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);
  void *decrypt(void *payload, void *aad, int payloadlen, int aadlen, uint64_t seqNo);
};

