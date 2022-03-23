#include "codeccapi.h"
#include <stdio.h>


//const CipherParams params = CipherParams{
//						"permanantdeaths!",
//						"eyeveeRaNdOm",
//            1,
//            "",
//            "01001598234293849238749283740983740928374190283741982",
//            "9d4db5ecd768198892531eebac72cf1d477dd0",
//            true};
//            //CipherSuite::TLS_AES_128_GCM_SHA256};

int main(void) {

	char message[26] = "0123456789";
	char aad[] = "";
	char enc_copy[27];

	char key[16] = "permanantdeaths!";
	char iv[13] = "eyeveeRaNdOm";

	MyCipherC *cipher = MyCipherC_create(key, 16, iv, 12);

	printf("%s\n", message);

	MyCipherC_encrypt(cipher, (void *)message, (void *)aad, 26, 0, 42);

	memcpy(enc_copy, message, 26); // "send message"
	enc_copy[26] = '\0';

	printf("%s\n", enc_copy);

	MyCipherC_decrypt(cipher, (void *)enc_copy, (void *)aad, 26, 0, 42);

	printf("%s\n", enc_copy);

	MyCipherC_destroy(cipher);

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