#include <stddef.h>
#include <stdint.h>

struct ReadCodecCiphersC;
typedef struct ReadCodecCiphersC ReadCodecCiphersC;

ReadCodecCiphersC* ReadCodecCiphersC_create();

void ReadCodecCiphersC_compute_ciphers(ReadCodecCiphersC*, uint8_t*, size_t);

void ReadCodecCiphersC_decrypt(ReadCodecCiphersC*, uint8_t*, size_t);

void ReadCodecCiphersC_destroy(ReadCodecCiphersC*);
