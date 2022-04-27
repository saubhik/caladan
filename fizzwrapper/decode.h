#pragma once

#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/handshake/Aead.h>
#include <quic/state/AckStates.h>

namespace quic {
QuicNodeType nodeType_;

// Cipher used to decrypt handshake packets.
std::unique_ptr<Aead> initialReadCipher_;

std::unique_ptr<Aead> oneRttReadCipher_;
std::unique_ptr<Aead> zeroRttReadCipher_;
std::unique_ptr<Aead> handshakeReadCipher_;

std::unique_ptr<PacketNumberCipher> initialHeaderCipher_;
std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher_;
std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher_;
std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher_;

// This contains the ack and packet number related states for all three
// packet number space.
AckStates ackStates;

extern void decrypt(void *data, size_t dataLen);
}
