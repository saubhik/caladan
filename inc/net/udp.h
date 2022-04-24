/*
 * udp.h - User Datagram Protocol
 */

#pragma once

#include <base/types.h>

#define CIPHER_OVERHEAD 16
#define CIPHER_META_SZ 41

/* For encryption in the iokernel. */
struct cipher_meta {
	unsigned long aead_index;
	unsigned long header_cipher_index;
	unsigned long packet_num;
	unsigned long header_len;
	unsigned long body_len;
	unsigned char header_form;
} __attribute__((packed));

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t chksum;
};
