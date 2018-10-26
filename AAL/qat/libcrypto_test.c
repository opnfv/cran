#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libcrypto.h"

#include "zuc.h"


#define DATA_SIZE 	(1024)
#define PKT_COUNT 	(2)


/* We need 1 x stat, 1 x libcrypt, min 1 x pdcp */
#define MIN_CORE_COUNT		(3)
#define MAX_CORE_COUNT		(8)

#define US_PER_SEC 			(1000000)

#define STAT_CORE_ID		(0)
#define LIBCRYPT_CORE_ID	(1)
#define FIRST_PDCP_CORE		(2)

#define SPEED_COUNT 		(14)

volatile uint8_t quit_signal;

static int stat_print(void);



struct wireless_test_data {
	struct {
		uint8_t data[64];
		unsigned len;
	} key;

	struct {
		uint8_t data[64] __rte_aligned(16);
		unsigned len;
	} cipher_iv;

	struct {
		uint8_t data[2048];
		unsigned len; /* length must be in Bits */
	} plaintext;

	struct {
		uint8_t data[2048];
		unsigned len; /* length must be in Bits */
	} ciphertext;

	struct {
		unsigned len;
	} validDataLenInBits;

	struct {
		unsigned len;
	} validCipherLenInBits;

	struct {
		unsigned len;
	} validAuthLenInBits;

	struct {
		uint8_t data[64];
		unsigned len;
	} auth_iv;

	struct {
		uint8_t data[64];
		unsigned len;
	} digest;
};


static struct wireless_test_data zuc_test_case_cipher_193b = {
	.key = {
		.data = {
			0x17, 0x3D, 0x14, 0xBA, 0x50, 0x03, 0x73, 0x1D,
			0x7A, 0x60, 0x04, 0x94, 0x70, 0xF0, 0x0A, 0x29
		},
		.len = 16
	},
	.cipher_iv = {
		.data = {
			0x66, 0x03, 0x54, 0x92, 0x78, 0x00, 0x00, 0x00,
			0x66, 0x03, 0x54, 0x92, 0x78, 0x00, 0x00, 0x00
		},
		.len = 16
	},
	.plaintext = {
		.data = {
			0x6C, 0xF6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xAB,
			0x0C, 0x97, 0x52, 0xFA, 0x6F, 0x90, 0x25, 0xFE,
			0x0B, 0xD6, 0x75, 0xD9, 0x00, 0x58, 0x75, 0xB2,
			0x00
		},
		.len = 200
	},
	.ciphertext = {
		.data = {
			0xA6, 0xC8, 0x5F, 0xC6, 0x6A, 0xFB, 0x85, 0x33,
			0xAA, 0xFC, 0x25, 0x18, 0xDF, 0xE7, 0x84, 0x94,
			0x0E, 0xE1, 0xE4, 0xB0, 0x30, 0x23, 0x8C, 0xC8,
			0x00
		},
		.len = 200
	},
	.validDataLenInBits = {
		.len = 193
	},
	.validCipherLenInBits = {
		.len = 193
	}
};


static struct wireless_test_data zuc_test_case_cipher_800b = {
	.key = {
		.data = {
			0xE5, 0xBD, 0x3E, 0xA0, 0xEB, 0x55, 0xAD, 0xE8,
			0x66, 0xC6, 0xAC, 0x58, 0xBD, 0x54, 0x30, 0x2A
		},
		.len = 16
	},
	.cipher_iv = {
		.data = {
			0x00, 0x05, 0x68, 0x23, 0xC4, 0x00, 0x00, 0x00,
			0x00, 0x05, 0x68, 0x23, 0xC4, 0x00, 0x00, 0x00
		},
		.len = 16
	},
	.plaintext = {
		.data = {
			0x14, 0xA8, 0xEF, 0x69, 0x3D, 0x67, 0x85, 0x07,
			0xBB, 0xE7, 0x27, 0x0A, 0x7F, 0x67, 0xFF, 0x50,
			0x06, 0xC3, 0x52, 0x5B, 0x98, 0x07, 0xE4, 0x67,
			0xC4, 0xE5, 0x60, 0x00, 0xBA, 0x33, 0x8F, 0x5D,
			0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22,
			0x46, 0xC8, 0x0D, 0x3B, 0x38, 0xF0, 0x7F, 0x4B,
			0xE2, 0xD8, 0xFF, 0x58, 0x05, 0xF5, 0x13, 0x22,
			0x29, 0xBD, 0xE9, 0x3B, 0xBB, 0xDC, 0xAF, 0x38,
			0x2B, 0xF1, 0xEE, 0x97, 0x2F, 0xBF, 0x99, 0x77,
			0xBA, 0xDA, 0x89, 0x45, 0x84, 0x7A, 0x2A, 0x6C,
			0x9A, 0xD3, 0x4A, 0x66, 0x75, 0x54, 0xE0, 0x4D,
			0x1F, 0x7F, 0xA2, 0xC3, 0x32, 0x41, 0xBD, 0x8F,
			0x01, 0xBA, 0x22, 0x0D
		},
		.len = 800
	},
	.ciphertext = {
		.data = {
			0x13, 0x1D, 0x43, 0xE0, 0xDE, 0xA1, 0xBE, 0x5C,
			0x5A, 0x1B, 0xFD, 0x97, 0x1D, 0x85, 0x2C, 0xBF,
			0x71, 0x2D, 0x7B, 0x4F, 0x57, 0x96, 0x1F, 0xEA,
			0x32, 0x08, 0xAF, 0xA8, 0xBC, 0xA4, 0x33, 0xF4,
			0x56, 0xAD, 0x09, 0xC7, 0x41, 0x7E, 0x58, 0xBC,
			0x69, 0xCF, 0x88, 0x66, 0xD1, 0x35, 0x3F, 0x74,
			0x86, 0x5E, 0x80, 0x78, 0x1D, 0x20, 0x2D, 0xFB,
			0x3E, 0xCF, 0xF7, 0xFC, 0xBC, 0x3B, 0x19, 0x0F,
			0xE8, 0x2A, 0x20, 0x4E, 0xD0, 0xE3, 0x50, 0xFC,
			0x0F, 0x6F, 0x26, 0x13, 0xB2, 0xF2, 0xBC, 0xA6,
			0xDF, 0x5A, 0x47, 0x3A, 0x57, 0xA4, 0xA0, 0x0D,
			0x98, 0x5E, 0xBA, 0xD8, 0x80, 0xD6, 0xF2, 0x38,
			0x64, 0xA0, 0x7B, 0x01
		},
		.len = 800
	},
	.validDataLenInBits = {
		.len = 800
	},
	.validCipherLenInBits = {
		.len = 800
	}
};

static struct wireless_test_data zuc_test_case_cipher_1570b = {
	.key = {
		.data = {
			0xD4, 0x55, 0x2A, 0x8F, 0xD6, 0xE6, 0x1C, 0xC8,
			0x1A, 0x20, 0x09, 0x14, 0x1A, 0x29, 0xC1, 0x0B
		},
		.len = 16
	},
	.cipher_iv = {
		.data = {
			0x76, 0x45, 0x2E, 0xC1, 0x14, 0x00, 0x00, 0x00,
			0x76, 0x45, 0x2E, 0xC1, 0x14, 0x00, 0x00, 0x00
		},
		.len = 16
	},
	.plaintext = {
		.data = {
			0x38, 0xF0, 0x7F, 0x4B, 0xE2, 0xD8, 0xFF, 0x58,
			0x05, 0xF5, 0x13, 0x22, 0x29, 0xBD, 0xE9, 0x3B,
			0xBB, 0xDC, 0xAF, 0x38, 0x2B, 0xF1, 0xEE, 0x97,
			0x2F, 0xBF, 0x99, 0x77, 0xBA, 0xDA, 0x89, 0x45,
			0x84, 0x7A, 0x2A, 0x6C, 0x9A, 0xD3, 0x4A, 0x66,
			0x75, 0x54, 0xE0, 0x4D, 0x1F, 0x7F, 0xA2, 0xC3,
			0x32, 0x41, 0xBD, 0x8F, 0x01, 0xBA, 0x22, 0x0D,
			0x3C, 0xA4, 0xEC, 0x41, 0xE0, 0x74, 0x59, 0x5F,
			0x54, 0xAE, 0x2B, 0x45, 0x4F, 0xD9, 0x71, 0x43,
			0x20, 0x43, 0x60, 0x19, 0x65, 0xCC, 0xA8, 0x5C,
			0x24, 0x17, 0xED, 0x6C, 0xBE, 0xC3, 0xBA, 0xDA,
			0x84, 0xFC, 0x8A, 0x57, 0x9A, 0xEA, 0x78, 0x37,
			0xB0, 0x27, 0x11, 0x77, 0x24, 0x2A, 0x64, 0xDC,
			0x0A, 0x9D, 0xE7, 0x1A, 0x8E, 0xDE, 0xE8, 0x6C,
			0xA3, 0xD4, 0x7D, 0x03, 0x3D, 0x6B, 0xF5, 0x39,
			0x80, 0x4E, 0xCA, 0x86, 0xC5, 0x84, 0xA9, 0x05,
			0x2D, 0xE4, 0x6A, 0xD3, 0xFC, 0xED, 0x65, 0x54,
			0x3B, 0xD9, 0x02, 0x07, 0x37, 0x2B, 0x27, 0xAF,
			0xB7, 0x92, 0x34, 0xF5, 0xFF, 0x43, 0xEA, 0x87,
			0x08, 0x20, 0xE2, 0xC2, 0xB7, 0x8A, 0x8A, 0xAE,
			0x61, 0xCC, 0xE5, 0x2A, 0x05, 0x15, 0xE3, 0x48,
			0xD1, 0x96, 0x66, 0x4A, 0x34, 0x56, 0xB1, 0x82,
			0xA0, 0x7C, 0x40, 0x6E, 0x4A, 0x20, 0x79, 0x12,
			0x71, 0xCF, 0xED, 0xA1, 0x65, 0xD5, 0x35, 0xEC,
			0x5E, 0xA2, 0xD4, 0xDF, 0x40
		},
		.len = 1576
	},
	.ciphertext = {
		.data = {
			0x83, 0x83, 0xB0, 0x22, 0x9F, 0xCC, 0x0B, 0x9D,
			0x22, 0x95, 0xEC, 0x41, 0xC9, 0x77, 0xE9, 0xC2,
			0xBB, 0x72, 0xE2, 0x20, 0x37, 0x81, 0x41, 0xF9,
			0xC8, 0x31, 0x8F, 0x3A, 0x27, 0x0D, 0xFB, 0xCD,
			0xEE, 0x64, 0x11, 0xC2, 0xB3, 0x04, 0x4F, 0x17,
			0x6D, 0xC6, 0xE0, 0x0F, 0x89, 0x60, 0xF9, 0x7A,
			0xFA, 0xCD, 0x13, 0x1A, 0xD6, 0xA3, 0xB4, 0x9B,
			0x16, 0xB7, 0xBA, 0xBC, 0xF2, 0xA5, 0x09, 0xEB,
			0xB1, 0x6A, 0x75, 0xDC, 0xAB, 0x14, 0xFF, 0x27,
			0x5D, 0xBE, 0xEE, 0xA1, 0xA2, 0xB1, 0x55, 0xF9,
			0xD5, 0x2C, 0x26, 0x45, 0x2D, 0x01, 0x87, 0xC3,
			0x10, 0xA4, 0xEE, 0x55, 0xBE, 0xAA, 0x78, 0xAB,
			0x40, 0x24, 0x61, 0x5B, 0xA9, 0xF5, 0xD5, 0xAD,
			0xC7, 0x72, 0x8F, 0x73, 0x56, 0x06, 0x71, 0xF0,
			0x13, 0xE5, 0xE5, 0x50, 0x08, 0x5D, 0x32, 0x91,
			0xDF, 0x7D, 0x5F, 0xEC, 0xED, 0xDE, 0xD5, 0x59,
			0x64, 0x1B, 0x6C, 0x2F, 0x58, 0x52, 0x33, 0xBC,
			0x71, 0xE9, 0x60, 0x2B, 0xD2, 0x30, 0x58, 0x55,
			0xBB, 0xD2, 0x5F, 0xFA, 0x7F, 0x17, 0xEC, 0xBC,
			0x04, 0x2D, 0xAA, 0xE3, 0x8C, 0x1F, 0x57, 0xAD,
			0x8E, 0x8E, 0xBD, 0x37, 0x34, 0x6F, 0x71, 0xBE,
			0xFD, 0xBB, 0x74, 0x32, 0xE0, 0xE0, 0xBB, 0x2C,
			0xFC, 0x09, 0xBC, 0xD9, 0x65, 0x70, 0xCB, 0x0C,
			0x0C, 0x39, 0xDF, 0x5E, 0x29, 0x29, 0x4E, 0x82,
			0x70, 0x3A, 0x63, 0x7F, 0x80
		},
		.len = 1576
	},
	.validDataLenInBits = {
		.len = 1570
	},
	.validCipherLenInBits = {
		.len = 1570
	}
};

static struct wireless_test_data zuc_test_case_cipher_2798b = {
	.key = {
		.data = {
			0xDB, 0x84, 0xB4, 0xFB, 0xCC, 0xDA, 0x56, 0x3B,
			0x66, 0x22, 0x7B, 0xFE, 0x45, 0x6F, 0x0F, 0x77
		},
		.len = 16
	},
	.cipher_iv = {
		.data = {
			0xE4, 0x85, 0x0F, 0xE1, 0x84, 0x00, 0x00, 0x00,
			0xE4, 0x85, 0x0F, 0xE1, 0x84, 0x00, 0x00, 0x00
		},
		.len = 16
	},
	.plaintext = {
		.data = {
			0xE5, 0x39, 0xF3, 0xB8, 0x97, 0x32, 0x40, 0xDA,
			0x03, 0xF2, 0xB8, 0xAA, 0x05, 0xEE, 0x0A, 0x00,
			0xDB, 0xAF, 0xC0, 0xE1, 0x82, 0x05, 0x5D, 0xFE,
			0x3D, 0x73, 0x83, 0xD9, 0x2C, 0xEF, 0x40, 0xE9,
			0x29, 0x28, 0x60, 0x5D, 0x52, 0xD0, 0x5F, 0x4F,
			0x90, 0x18, 0xA1, 0xF1, 0x89, 0xAE, 0x39, 0x97,
			0xCE, 0x19, 0x15, 0x5F, 0xB1, 0x22, 0x1D, 0xB8,
			0xBB, 0x09, 0x51, 0xA8, 0x53, 0xAD, 0x85, 0x2C,
			0xE1, 0x6C, 0xFF, 0x07, 0x38, 0x2C, 0x93, 0xA1,
			0x57, 0xDE, 0x00, 0xDD, 0xB1, 0x25, 0xC7, 0x53,
			0x9F, 0xD8, 0x50, 0x45, 0xE4, 0xEE, 0x07, 0xE0,
			0xC4, 0x3F, 0x9E, 0x9D, 0x6F, 0x41, 0x4F, 0xC4,
			0xD1, 0xC6, 0x29, 0x17, 0x81, 0x3F, 0x74, 0xC0,
			0x0F, 0xC8, 0x3F, 0x3E, 0x2E, 0xD7, 0xC4, 0x5B,
			0xA5, 0x83, 0x52, 0x64, 0xB4, 0x3E, 0x0B, 0x20,
			0xAF, 0xDA, 0x6B, 0x30, 0x53, 0xBF, 0xB6, 0x42,
			0x3B, 0x7F, 0xCE, 0x25, 0x47, 0x9F, 0xF5, 0xF1,
			0x39, 0xDD, 0x9B, 0x5B, 0x99, 0x55, 0x58, 0xE2,
			0xA5, 0x6B, 0xE1, 0x8D, 0xD5, 0x81, 0xCD, 0x01,
			0x7C, 0x73, 0x5E, 0x6F, 0x0D, 0x0D, 0x97, 0xC4,
			0xDD, 0xC1, 0xD1, 0xDA, 0x70, 0xC6, 0xDB, 0x4A,
			0x12, 0xCC, 0x92, 0x77, 0x8E, 0x2F, 0xBB, 0xD6,
			0xF3, 0xBA, 0x52, 0xAF, 0x91, 0xC9, 0xC6, 0xB6,
			0x4E, 0x8D, 0xA4, 0xF7, 0xA2, 0xC2, 0x66, 0xD0,
			0x2D, 0x00, 0x17, 0x53, 0xDF, 0x08, 0x96, 0x03,
			0x93, 0xC5, 0xD5, 0x68, 0x88, 0xBF, 0x49, 0xEB,
			0x5C, 0x16, 0xD9, 0xA8, 0x04, 0x27, 0xA4, 0x16,
			0xBC, 0xB5, 0x97, 0xDF, 0x5B, 0xFE, 0x6F, 0x13,
			0x89, 0x0A, 0x07, 0xEE, 0x13, 0x40, 0xE6, 0x47,
			0x6B, 0x0D, 0x9A, 0xA8, 0xF8, 0x22, 0xAB, 0x0F,
			0xD1, 0xAB, 0x0D, 0x20, 0x4F, 0x40, 0xB7, 0xCE,
			0x6F, 0x2E, 0x13, 0x6E, 0xB6, 0x74, 0x85, 0xE5,
			0x07, 0x80, 0x4D, 0x50, 0x45, 0x88, 0xAD, 0x37,
			0xFF, 0xD8, 0x16, 0x56, 0x8B, 0x2D, 0xC4, 0x03,
			0x11, 0xDF, 0xB6, 0x54, 0xCD, 0xEA, 0xD4, 0x7E,
			0x23, 0x85, 0xC3, 0x43, 0x62, 0x03, 0xDD, 0x83,
			0x6F, 0x9C, 0x64, 0xD9, 0x74, 0x62, 0xAD, 0x5D,
			0xFA, 0x63, 0xB5, 0xCF, 0xE0, 0x8A, 0xCB, 0x95,
			0x32, 0x86, 0x6F, 0x5C, 0xA7, 0x87, 0x56, 0x6F,
			0xCA, 0x93, 0xE6, 0xB1, 0x69, 0x3E, 0xE1, 0x5C,
			0xF6, 0xF7, 0xA2, 0xD6, 0x89, 0xD9, 0x74, 0x17,
			0x98, 0xDC, 0x1C, 0x23, 0x8E, 0x1B, 0xE6, 0x50,
			0x73, 0x3B, 0x18, 0xFB, 0x34, 0xFF, 0x88, 0x0E,
			0x16, 0xBB, 0xD2, 0x1B, 0x47, 0xAC
		},
		.len = 2800
	},
	.ciphertext = {
		.data = {
			0x4B, 0xBF, 0xA9, 0x1B, 0xA2, 0x5D, 0x47, 0xDB,
			0x9A, 0x9F, 0x19, 0x0D, 0x96, 0x2A, 0x19, 0xAB,
			0x32, 0x39, 0x26, 0xB3, 0x51, 0xFB, 0xD3, 0x9E,
			0x35, 0x1E, 0x05, 0xDA, 0x8B, 0x89, 0x25, 0xE3,
			0x0B, 0x1C, 0xCE, 0x0D, 0x12, 0x21, 0x10, 0x10,
			0x95, 0x81, 0x5C, 0xC7, 0xCB, 0x63, 0x19, 0x50,
			0x9E, 0xC0, 0xD6, 0x79, 0x40, 0x49, 0x19, 0x87,
			0xE1, 0x3F, 0x0A, 0xFF, 0xAC, 0x33, 0x2A, 0xA6,
			0xAA, 0x64, 0x62, 0x6D, 0x3E, 0x9A, 0x19, 0x17,
			0x51, 0x9E, 0x0B, 0x97, 0xB6, 0x55, 0xC6, 0xA1,
			0x65, 0xE4, 0x4C, 0xA9, 0xFE, 0xAC, 0x07, 0x90,
			0xD2, 0xA3, 0x21, 0xAD, 0x3D, 0x86, 0xB7, 0x9C,
			0x51, 0x38, 0x73, 0x9F, 0xA3, 0x8D, 0x88, 0x7E,
			0xC7, 0xDE, 0xF4, 0x49, 0xCE, 0x8A, 0xBD, 0xD3,
			0xE7, 0xF8, 0xDC, 0x4C, 0xA9, 0xE7, 0xB7, 0x33,
			0x14, 0xAD, 0x31, 0x0F, 0x90, 0x25, 0xE6, 0x19,
			0x46, 0xB3, 0xA5, 0x6D, 0xC6, 0x49, 0xEC, 0x0D,
			0xA0, 0xD6, 0x39, 0x43, 0xDF, 0xF5, 0x92, 0xCF,
			0x96, 0x2A, 0x7E, 0xFB, 0x2C, 0x85, 0x24, 0xE3,
			0x5A, 0x2A, 0x6E, 0x78, 0x79, 0xD6, 0x26, 0x04,
			0xEF, 0x26, 0x86, 0x95, 0xFA, 0x40, 0x03, 0x02,
			0x7E, 0x22, 0xE6, 0x08, 0x30, 0x77, 0x52, 0x20,
			0x64, 0xBD, 0x4A, 0x5B, 0x90, 0x6B, 0x5F, 0x53,
			0x12, 0x74, 0xF2, 0x35, 0xED, 0x50, 0x6C, 0xFF,
			0x01, 0x54, 0xC7, 0x54, 0x92, 0x8A, 0x0C, 0xE5,
			0x47, 0x6F, 0x2C, 0xB1, 0x02, 0x0A, 0x12, 0x22,
			0xD3, 0x2C, 0x14, 0x55, 0xEC, 0xAE, 0xF1, 0xE3,
			0x68, 0xFB, 0x34, 0x4D, 0x17, 0x35, 0xBF, 0xBE,
			0xDE, 0xB7, 0x1D, 0x0A, 0x33, 0xA2, 0xA5, 0x4B,
			0x1D, 0xA5, 0xA2, 0x94, 0xE6, 0x79, 0x14, 0x4D,
			0xDF, 0x11, 0xEB, 0x1A, 0x3D, 0xE8, 0xCF, 0x0C,
			0xC0, 0x61, 0x91, 0x79, 0x74, 0xF3, 0x5C, 0x1D,
			0x9C, 0xA0, 0xAC, 0x81, 0x80, 0x7F, 0x8F, 0xCC,
			0xE6, 0x19, 0x9A, 0x6C, 0x77, 0x12, 0xDA, 0x86,
			0x50, 0x21, 0xB0, 0x4C, 0xE0, 0x43, 0x95, 0x16,
			0xF1, 0xA5, 0x26, 0xCC, 0xDA, 0x9F, 0xD9, 0xAB,
			0xBD, 0x53, 0xC3, 0xA6, 0x84, 0xF9, 0xAE, 0x1E,
			0x7E, 0xE6, 0xB1, 0x1D, 0xA1, 0x38, 0xEA, 0x82,
			0x6C, 0x55, 0x16, 0xB5, 0xAA, 0xDF, 0x1A, 0xBB,
			0xE3, 0x6F, 0xA7, 0xFF, 0xF9, 0x2E, 0x3A, 0x11,
			0x76, 0x06, 0x4E, 0x8D, 0x95, 0xF2, 0xE4, 0x88,
			0x2B, 0x55, 0x00, 0xB9, 0x32, 0x28, 0xB2, 0x19,
			0x4A, 0x47, 0x5C, 0x1A, 0x27, 0xF6, 0x3F, 0x9F,
			0xFD, 0x26, 0x49, 0x89, 0xA1, 0xBC
		},
		.len = 2800
	},
	.validDataLenInBits = {
		.len = 2798
	},
	.validCipherLenInBits = {
		.len = 2798
	}
};



int null_callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count);
int nectar_zuc_callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count);
int sequence_callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count);

static void int_handler(int sig_num) {
  printf("\nExiting on signal %d\n", sig_num);
  quit_signal = 1;
}

uint8_t core_count;


typedef struct {
	uint8_t 		  	id;
	volatile uint64_t 	pkts_rx;
	volatile uint64_t 	pkts_tx;

	volatile uint64_t 	data_rx;
	volatile uint64_t 	data_tx;

	volatile uint64_t 	next_pkt_sequence;
} worker_s;

volatile worker_s workers[MAX_CORE_COUNT];

uint32_t 	callback_pkt_count[MAX_SEC_CTX];
uint8_t 	cipher_text	[MAX_SEC_CTX][PKT_COUNT][DATA_SIZE];

uint8_t 	data_in		[MAX_SEC_CTX][PKT_COUNT][DATA_SIZE];
uint8_t 	data_out	[MAX_SEC_CTX][PKT_COUNT][DATA_SIZE];


#define TEST_HEXDUMP(file, title, buf, len) rte_hexdump(file, title, buf, len)


#if 0
typedef uint32_t u32;
typedef uint8_t u8;


/*the state registers of LFSR*/
u32 LFSR_S[16] = {0};

/*the registers of F*/
u32 F_R1 = 0;
u32 F_R2 = 0;

/*the outputs of BitReorganization*/
u32 BRC_X[4] = {0};

/*the s-boxes*/
u8 S0[256] = {
    0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb, 
    0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90, 
    0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac, 
    0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38, 
    0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b, 
    0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c, 
    0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad, 
    0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8, 
    0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56, 
    0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe, 
    0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d, 
    0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23, 
    0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1, 
    0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f, 
    0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65, 
    0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60 
};

u8 S1[256] = {
    0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77, 
    0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42, 
    0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1, 
    0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48, 
    0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87, 
    0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb, 
    0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09, 
    0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9, 
    0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9, 
    0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89, 
    0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4, 
    0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde, 
    0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21, 
    0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34, 
    0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28, 
    0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2 
};

/*the constants D*/ 
u32 EK_d[16] = { 
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC 
};

u32 AddM(u32 a, u32 b)
{
    u32 c = a + b;
    return (c & 0x7FFFFFFF) + (c >> 31);
}

/*LFSR with initialization mode*/
#define MulByPow2(x, k) ((((x) << k) | ((x) >> (31 - k))) & 0x7FFFFFFF)
void LFSRWithInitializationMode(u32 u)
{
    u32 f, v;
    u32 i;

    f = LFSR_S[0];
    v = MulByPow2(LFSR_S[0], 8);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[4], 20);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[10], 21);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[13], 17);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[15], 15);
    f = AddM(f, v);

    f = AddM(f, u);

    /*update the state*/
    for(i=0; i<15; i++)
    {
        LFSR_S[i] = LFSR_S[i+1];
    }
    LFSR_S[15] = f;
}

/* LFSR with work mode */ 
void LFSRWithWorkMode() 
{ 
    u32 f, v;
    u32 i;

    f = LFSR_S[0];
    v = MulByPow2(LFSR_S[0], 8);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[4], 20);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[10], 21);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[13], 17);
    f = AddM(f, v);

    v = MulByPow2(LFSR_S[15], 15);
    f = AddM(f, v);

    /*update the state*/
    for(i=0; i<15; i++)
    {
        LFSR_S[i] = LFSR_S[i+1];
    }
    LFSR_S[15] = f;
}

/*Bit Reorganization*/
void BitReorganization()
{
    BRC_X[0] = ((LFSR_S[15] & 0x7FFF8000) << 1) | (LFSR_S[14] & 0xFFFF);
    BRC_X[1] = ((LFSR_S[11] & 0xFFFF) << 16) | (LFSR_S[9] >> 15);
    BRC_X[2] = ((LFSR_S[7] & 0xFFFF) << 16) | (LFSR_S[5] >> 15);
    BRC_X[3] = ((LFSR_S[2] & 0xFFFF) << 16) | (LFSR_S[0] >> 15);
}

#define ROT(a, k) (((a) << k) | ((a) >> (32 - k)))

/*L1*/
u32 L1(u32 X)
{
    return (X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24));
}

/*L2*/
u32 L2(u32 X)
{
    return (X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30));
}

#define MAKEU32(a, b, c ,d) (((u32)(a) << 24) | ((u32)(b) << 16) | ((u32)(c) << 8) | ((u32)(d)))
/*F*/
u32 F()
{
    u32 W, W1, W2, u, v;

    W = (BRC_X[0] ^ F_R1) + F_R2;
    W1 = F_R1 + BRC_X[1];
    W2 = F_R2 ^ BRC_X[2];
    u = L1((W1 << 16) | (W2 >> 16));
    v = L2((W2 << 16) | (W1 >> 16));
    F_R1 = MAKEU32(S0[u >> 24], S1[(u >> 16) & 0xFF], S0[(u >> 8) & 0xFF], S1[u & 0xFF]);
    F_R2 = MAKEU32(S0[v >> 24], S1[(v >> 16) & 0xFF], S0[(v >> 8) & 0xFF], S1[v & 0xFF]);

    return W;
}

#define MAKEU31(a, b, c) (((u32)((u32)(0) | (u8)(a)) << 23) | ((u32)(b) << 8) | (u32)((u32)(0) | (u8)(c)))
/*initialize*/
void Initialization(u8* k, u8* iv)
{
    u32 w, nCount;
    u32 i;

    /* expand key */
    for (i=0; i<16; i++)
    {
        LFSR_S[i] = MAKEU31(k[i], EK_d[i], iv[i]);
    }

    /*set F_R1 and F_R2 to zero*/
    F_R1 = 0;
    F_R2 = 0;
    nCount = 32;
    while (nCount > 0)
    {
        BitReorganization();
        w = F();
        LFSRWithInitializationMode(w >> 1);
        nCount--;
    }

    /*First generation, abandoned*/
    BitReorganization();
    F();
    LFSRWithWorkMode();
}

void GenerateKeyStream(u32 *pKeyStream, u32 KeyStreamLen)
{
    u32 i;

    for (i=0; i<KeyStreamLen; i++)
    {
        BitReorganization();
        pKeyStream[i] = F() ^ BRC_X[3];
        LFSRWithWorkMode();
    }
}



void RevertData(u8 *Data, u32 Len)
{
    u32 i = 0;
    u8 tData = 0;

    for (i=0; i<Len/2; i++)
    {
        tData = Data[i];
        Data[i] = Data[Len-i-1];
        Data[Len-i-1] = tData;
    }
}

int IsLittleEndian()
{
    u32 t1 = 0x31;

    if ((*(u8*)(&t1)) == 0x31)
    {
        return 1;
    }

    return 0;
}

/*Length of COUNT is 4*/
void EEA3_new(u8 *CK, u8 *COUNT, u8 BEARER, u8 DIRECTION, u8 *M, u32 LENGTH, u8 *CM)
{
    u8 IV[16] = {0};
    u32 i = 0, j = 0, tKeyStreamU32 = 0;
    u8 *tKeyStreamU8 = (u8*)&tKeyStreamU32;
    u32 bLENGTH = 0; //Byte LENGTH
    u32 lbLENGTH = 0; //Left Byte LENGTH
    u8 bMask = 0, bFlag = 0;

    IV[0] = COUNT[0];
    IV[1] = COUNT[1];
    IV[2] = COUNT[2];
    IV[3] = COUNT[3];

    IV[4] = ((BEARER << 3) | ((DIRECTION & 1)<<2)) & 0xFC;
    IV[5] = IV[6] = IV[7] = 0;

    IV[8] = IV[0];
    IV[9] = IV[1];
    IV[10] = IV[2];
    IV[11] = IV[3];
    IV[12] = IV[4];
    IV[13] = IV[5];
    IV[14] = IV[6];
    IV[15] = IV[7];

    bLENGTH = LENGTH / 8;
    lbLENGTH = LENGTH % 8;

    Initialization(CK, IV);

    for (i=0; i<bLENGTH; i++)
    {
        if ((i%4) == 0)
        {
            GenerateKeyStream(&tKeyStreamU32, 1);
            if (IsLittleEndian())
            {
                RevertData(tKeyStreamU8, 4);
            }
        }

        CM[i] = tKeyStreamU8[i%4] ^ M[i];
    }

    if (lbLENGTH)
    {   
        if ((i%4) == 0)
        {
            GenerateKeyStream(&tKeyStreamU32, 1);
            if (IsLittleEndian())
            {
                RevertData(tKeyStreamU8, 4);
            }
        }

        bMask = 0;
        bFlag = 0x80;
        for (j=0; j<lbLENGTH; j++)
        {
            bMask |= bFlag;
            bFlag >>= 1;
        }

        CM[i] = ((tKeyStreamU8[i%4] ^ M[i]) & bMask);
    }
}



#endif












static int pdcp_zuc_cipher_worker(void *p) {

	uint64_t worker_id = (uint64_t)p;

	uint32_t i, pkt = 0;
	int retval = 0;

	iv_t 				iv[PKT_COUNT];
	symmetric_key_t 	sym_key;

    memset(&iv[pkt], 0 , sizeof(iv_t));
    iv[pkt].counter = (zuc_test_case_cipher_193b.cipher_iv.data[0] << 24); 
    iv[pkt].counter |= zuc_test_case_cipher_193b.cipher_iv.data[1] << 16; 
    iv[pkt].counter |= zuc_test_case_cipher_193b.cipher_iv.data[2] << 8; 
    iv[pkt].counter |= zuc_test_case_cipher_193b.cipher_iv.data[3]; 

    iv[pkt].bearer = ((zuc_test_case_cipher_193b.cipher_iv.data[4] & 0xF8) >> 3);
    iv[pkt].direction = (zuc_test_case_cipher_193b.cipher_iv.data[4] & 0x4) >> 2; 

    for (pkt = 0; pkt < PKT_COUNT; ++pkt) {
		for (i = 0; i < DATA_SIZE; ++i) {
			data_in[worker_id][pkt][i] = zuc_test_case_cipher_193b.plaintext.data[i];
		}
	}

	for (i = 0; i < KEY_SIZE; ++i) {
		sym_key[i] = zuc_test_case_cipher_193b.key.data[i];
	}
#if 0
    pkt = 0;
//	for (pkt = 0; pkt < PKT_COUNT; ++pkt) 
    {
#if 1
        memset(cipher_text[worker_id][pkt], 0, zuc_test_case_cipher_193b.plaintext.len/8);
		EEA3(sym_key, iv[pkt].counter, iv[pkt].bearer, iv[pkt].direction,  \
                zuc_test_case_cipher_193b.plaintext.len, \
                (uint32_t*)data_in[worker_id][pkt], \
                (uint32_t*)cipher_text[worker_id][pkt] );
#else
#if 0
        EEA3_new(sym_key, iv[pkt].counter, iv[pkt].bearer, iv[pkt].direction,
                zuc_test_case_cipher_193b.plaintext.len, (uint32_t*)data_in[worker_id][pkt], (uint32_t*)cipher_text[worker_id][pkt] );
#else

        EEA3_new(sym_key, &iv[pkt].counter, iv[pkt].bearer, iv[pkt].direction,
                (u8 *)data_in[worker_id][pkt], zuc_test_case_cipher_193b.plaintext.len, (u8 *)cipher_text[worker_id][pkt] );
#endif
#endif
        
	    TEST_HEXDUMP(stdout, "key:", sym_key, KEY_SIZE);
    	TEST_HEXDUMP(stdout, "plaintext:", data_in, zuc_test_case_cipher_193b.plaintext.len/8);
    	TEST_HEXDUMP(stdout, "ciphertext:", cipher_text[worker_id][pkt], zuc_test_case_cipher_193b.plaintext.len/8);


        TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(
	                &cipher_text[worker_id][pkt],
		            zuc_test_case_cipher_193b.ciphertext.data,
		            zuc_test_case_cipher_193b.validDataLenInBits.len,
		            "ZUC Ciphertext data not as expected");
        printf("xxxxxxxxxxxxxx Nectar zuc cipher as expected\n");
    }
#endif
	
    
    //data_ctx_t data_ctx = (data_ctx_t)worker_id+34;
    data_ctx_t data_ctx = 0x34;
	sec_ctx_t sec_ctx = nt_crypto_new_security_context(ZUC, sym_key, data_ctx);
	if(NULL == sec_ctx){
		printf("Error creating new security context!\n");
		return -1;
	}

    sec_ctx_t sec_ctx2 = nt_crypto_new_security_context(ZUC, sym_key, data_ctx);
	if(NULL == sec_ctx){
		printf("Error creating new security context!\n");
		return -1;
	}
    
	pkt = 0;
	callback_pkt_count[worker_id] = 0;

	// uint16_t len = 0;

    int _signal = 20000001;
    //int _signal = 640;
 	while ((_signal--) ) {


		retval = nt_crypto_cipher(sec_ctx, &iv[pkt], data_in[worker_id][pkt], data_out[worker_id][pkt], 
                zuc_test_case_cipher_193b.plaintext.len/8);
		if( unlikely(retval) ){
			printf("nt_crypto_cipher did not cipher!?!\n");
			continue;
		}
		workers[worker_id].pkts_tx++;
        //rte_pause();
//        printf("_signal = %d\n", _signal);
//		pkt = (pkt + 1) % PKT_COUNT;
    }
	quit_signal = 0;

        printf("xxxxxxxxxxxxxxxxx _signal = %d\n", _signal);
    return 0;
}


int nectar_zuc_callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count) {

    static int count = 1;
	uint64_t idx = (uint64_t)data_ctx;
	workers[idx].pkts_rx += burst_count;

	int retval = 0;

	TEST_HEXDUMP(stdout, "data out:", data_out[0].data, data_out[0].length);
	/* Validate obuf */
    TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(
		data_out[0].data,
		zuc_test_case_cipher_193b.ciphertext.data,
		zuc_test_case_cipher_193b.validDataLenInBits.len,
		"ZUC Ciphertext data not as expected");
    printf("Nectar zuc cipher as expected %d times\n", count++);

#if 0
	for ( j = 0; j < burst_count; ++j) {
		workers[idx].data_rx += data_out[j].length;

		// printf("got len: %d\n", data_out[j].length);
		for (i = 0; i < data_out[i].length; ++i) {
		// for (i = 0; i < 4; ++i) {

			if(data_out[j].data[i] != cipher_text[idx][ callback_pkt_count[idx] ][i] ) {
				//printf("\nError in callback: plain != cipher: %02x != %02x\n", data_out[j].data[i], cipher_text[idx][0][i]  );

				printf("worker %ld with pkt %d has len: %d\n", idx, callback_pkt_count[idx],  data_out[j].length);
				printf("Expected:\n");
				for (k = 0; k < data_out[j].length; ++k) {
					printf("%02x ", cipher_text[idx][ callback_pkt_count[idx] ][k]);
				}
				printf("\ngot:     \n");
				for (k = 0; k < data_out[j].length; ++k) {
					printf("%02x ", data_out[j].data[k]);
				}
				printf("\n");

				if(0 != j){
					printf("length of prev: %d\n", data_out[j-1].length);
				}

				retval = -1;
				// return -1;
			}
		}
		callback_pkt_count[idx] = (callback_pkt_count[idx] + 1) % PKT_COUNT;
	}
	// printf("\n");

#endif
	return retval;
}

int main(int argc, char *argv[]) {

	uint8_t portid, core;
	quit_signal = 0;

	/* Catch ctrl-c so we can print on exit. */
	signal(SIGINT, int_handler);

	// srand(4);

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	core_count = rte_lcore_count();
	if ( MIN_CORE_COUNT > core_count ) {
		printf("\nERROR: Need at least %i cores.\n", MIN_CORE_COUNT);
		return -1;
	}

	uint8_t nb_ports = rte_eth_dev_count();

	// int retval = nt_crypto_init(null_callback, LIBCRYPT_CORE_ID);
	int retval = nt_crypto_init(nectar_zuc_callback, LIBCRYPT_CORE_ID);
	// int retval = nt_crypto_init(sequence_callback, LIBCRYPT_CORE_ID);
	if(retval){
		printf("Error in nt_crypto_init\n");
		return -1;
	}

	/* Start security contexts from the first free core - after the libcrypto thread. */
	//for (core = FIRST_PDCP_CORE; core < core_count; ++core) {
	for (core = FIRST_PDCP_CORE; core < FIRST_PDCP_CORE +1; ++core) {
		printf("Launching worker on core: %d\n", core);
		uint64_t idx = core - FIRST_PDCP_CORE;
		rte_eal_remote_launch((lcore_function_t *)pdcp_zuc_cipher_worker, (void*)idx, core);

		usleep(10000);
	}

//	stat_print();



	RTE_LCORE_FOREACH_SLAVE(core) {
	if (rte_eal_wait_lcore(core) < 0)
		return -1;
	}

	nt_crypto_end();
	for (portid = 0; portid < nb_ports; portid++) {
		printf("Closing port %i\n", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
	return 0;
}


static int stat_print(void) {

	uint64_t total_pkt_tx;
	uint64_t total_pkt_rx;

	uint64_t total_data_rx;
	uint64_t prev_total_data_rx = 0;

	// uint64_t prev_total_pkt_tx = 0;

	while ( !quit_signal ) {
		sleep(1);

		total_pkt_tx = 0;
		total_pkt_rx = 0;
		total_data_rx = 0;

		uint8_t i;
		for (i = 0; i < core_count; ++i) {
			total_pkt_tx += workers[i].pkts_tx;
			total_pkt_rx += workers[i].pkts_rx;

			total_data_rx += workers[i].data_rx;
		}

		// uint64_t packets_1_sec = total_pkt_tx - prev_total_pkt_tx;
		// prev_total_pkt_tx = total_pkt_tx;

		uint64_t byte_per_sec = total_data_rx - prev_total_data_rx;
		prev_total_data_rx = total_data_rx;

		double mbps = (byte_per_sec * 8 )  / 1000.0 / 1000.0;
		double mpps = (mbps / 8.0) / DATA_SIZE;
		printf("TX: %ld\tRX: %ld\tinflight: %ld\tbw: %0.0f Mb/s\tmpps: %0.1f\n", total_pkt_tx, total_pkt_rx, total_pkt_tx - total_pkt_rx, mbps, mpps );

	}

  return 0;
}
