#ifndef _LIBCRYPTO_H_
#define _LIBCRYPTO_H_

/** NT libcrypto API version 0.7

version 0.7
- Performance in 13Gbit/s range - potential limited by virtual channels.
- Multiple security contexts are now supported.
- Heavy memory usage, due to worst case return address storrage.

version 0.6
- ???

The library will encapsulate the Cipher Offload Engine running on the NT SmartNic.

The accelerated functionality can be utilized via the following types and calls:
*/

#include <stdint.h>





#define CRYPTODEV_NAME_QAT_SYM_PMD crypto_qat
#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1
#define DEFAULT_NUM_OPS_INFLIGHT        (128)



#define TEST_SUCCESS  (0)
#define TEST_FAILED  (-1)

#ifndef TEST_TRACE_FAILURE
# define TEST_TRACE_FAILURE(_file, _line, _func)
#endif



#define TEST_ASSERT(cond, msg, ...) do {                         \
		if (!(cond)) {                                           \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

#define TEST_ASSERT_EQUAL(a, b, msg, ...) do {                   \
		if (!(a == b)) {                                         \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

/* Compare two buffers (length in bytes) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL(a, b, len,  msg, ...) do {	\
	if (memcmp(a, b, len)) {                                        \
		printf("TestCase %s() line %d failed: "              \
			msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
		TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
		return TEST_FAILED;                                  \
	}                                                        \
} while (0)

/* Compare two buffers with offset (length and offset in bytes) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_OFFSET(a, b, len, off, msg, ...) do { \
	const uint8_t *_a_with_off = (const uint8_t *)a + off;              \
	const uint8_t *_b_with_off = (const uint8_t *)b + off;              \
	TEST_ASSERT_BUFFERS_ARE_EQUAL(_a_with_off, _b_with_off, len, msg);  \
} while (0)

/* Compare two buffers (length in bits) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(a, b, len, msg, ...) do {	\
	uint8_t _last_byte_a, _last_byte_b;                       \
	uint8_t _last_byte_mask, _last_byte_bits;                  \
	TEST_ASSERT_BUFFERS_ARE_EQUAL(a, b, (len >> 3), msg);     \
	if (len % 8) {                                              \
		_last_byte_bits = len % 8;                   \
		_last_byte_mask = ~((1 << (8 - _last_byte_bits)) - 1); \
		_last_byte_a = ((const uint8_t *)a)[len >> 3];            \
		_last_byte_b = ((const uint8_t *)b)[len >> 3];            \
		_last_byte_a &= _last_byte_mask;                     \
		_last_byte_b &= _last_byte_mask;                    \
		if (_last_byte_a != _last_byte_b) {                  \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);\
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
	}                                                            \
} while (0)

/* Compare two buffers with offset (length and offset in bits) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT_OFFSET(a, b, len, off, msg, ...) do {	\
	uint8_t _first_byte_a, _first_byte_b;                                 \
	uint8_t _first_byte_mask, _first_byte_bits;                           \
	uint32_t _len_without_first_byte = (off % 8) ?                       \
				len - (8 - (off % 8)) :                       \
				len;                                          \
	uint32_t _off_in_bytes = (off % 8) ? (off >> 3) + 1 : (off >> 3);     \
	const uint8_t *_a_with_off = (const uint8_t *)a + _off_in_bytes;      \
	const uint8_t *_b_with_off = (const uint8_t *)b + _off_in_bytes;      \
	TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(_a_with_off, _b_with_off,           \
				_len_without_first_byte, msg);                \
	if (off % 8) {                                                        \
		_first_byte_bits = 8 - (off % 8);                             \
		_first_byte_mask = (1 << _first_byte_bits) - 1;               \
		_first_byte_a = *(_a_with_off - 1);                           \
		_first_byte_b = *(_b_with_off - 1);                           \
		_first_byte_a &= _first_byte_mask;                            \
		_first_byte_b &= _first_byte_mask;                            \
		if (_first_byte_a != _first_byte_b) {                         \
			printf("TestCase %s() line %d failed: "               \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__); \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);     \
			return TEST_FAILED;                                   \
		}                                                             \
	}                                                                     \
} while (0)

#define TEST_ASSERT_NOT_EQUAL(a, b, msg, ...) do {               \
		if (!(a != b)) {                                         \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

#define TEST_ASSERT_SUCCESS(val, msg, ...) do {                  \
		typeof(val) _val = (val);                                \
		if (!(_val == 0)) {                                      \
			printf("TestCase %s() line %d failed (err %d): "     \
				msg "\n", __func__, __LINE__, _val,              \
				##__VA_ARGS__);                                  \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

#define TEST_ASSERT_FAIL(val, msg, ...) do {                     \
		if (!(val != 0)) {                                       \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

#define TEST_ASSERT_NULL(val, msg, ...) do {                     \
		if (!(val == NULL)) {                                    \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

#define TEST_ASSERT_NOT_NULL(val, msg, ...) do {                 \
		if (!(val != NULL)) {                                    \
			printf("TestCase %s() line %d failed: "              \
				msg "\n", __func__, __LINE__, ##__VA_ARGS__);    \
			TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);    \
			return TEST_FAILED;                                  \
		}                                                        \
} while (0)

typedef uint8_t *data_t;

typedef struct {
    data_t data_in;
    data_t data_out;
    uint16_t length;
    uint8_t pad[2];
}cipher_input;

#define KEY_SIZE        (16)
#define MAX_BURST_SIZE  (32)

#define MAX_SEC_CTX     (8)        /* The number of concurrently running security contexts. */

#define MAXIMUM_IV_LENGTH				(16)

/* The plain- and cipher-text type. */


typedef struct {
   data_t   data;
   uint16_t length;
} data_out_t;

/* The reference to a security context, which hold the internal state of an encryption tunnel. */
typedef void 	*sec_ctx_t;

/* The reference to the data context - will be given with each ciphering and returned with the callback. */
typedef void 	*data_ctx_t;

/* The symmetric encryption key. */
typedef uint8_t symmetric_key_t[KEY_SIZE];

/* The initialization vector. */
typedef struct __attribute__((packed)) {
    uint32_t    counter;
    unsigned    bearer      : 5;
    unsigned    direction   : 1;
    uint8_t     padding[3];
} iv_t;

/* Crypto algorithm selection. */
typedef enum { LOOPBACK = 0x0, ZUC = 0x3 } algo_type_t;

/*
The callback for data return.

When the callback returns, the data_out array will be destroyed.

Input:
- data_ctx  : The reference to the data context in which the packet exist.
- data_out  : An array of pointers to data that has been returned.
- count     : The number of array elements in data_out.
Return:
- 0         : Operation successful
- non-zero  : Operation failed
*/
typedef int (*callback_t)(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t count);

/*
Crypto library initializer

Input:
- callback  : The callback for burst data return.
- core      : The DPDK core used to run the library.
Return:
- 0         : Operation successful
- non-zero  : Operation failed
*/
int nt_crypto_init(callback_t callback, uint8_t core);

/*
Setup and return a new security context.

Input:
- algo_type : Algorithm selection.
- key       : The encryption key.
- data_ctx  : A data context for each PDU encrypted within the security context.
Return:
- ptr       : A void pointer to the security context.
- NULL      : Operation failed.
*/
sec_ctx_t nt_crypto_new_security_context(algo_type_t algo_type, symmetric_key_t key, data_ctx_t data_ctx);

/*
Encryption and decryption of data:

Input:
- sec_ctx   : The security context, thus key, used to cipher the data.
- iv        : The initialization vector used to cipher the data.
- cipher_input   : The pointer to the input buffer.
-  nb_cipher		The number of operations to process.
 - Return  :  The number of packets which are ciphered/deciphered successfully.
*/
int nt_crypto_cipher(sec_ctx_t sec_ctx, iv_t *iv, cipher_input *crypto_input, uint16_t nb_cipher);

/*
End a given security context, all in-flight data is lost.

Will return when security context and all related resources has be closed and freed.

Input:
- sec_ctx   : The security context to be closed.
Return:
- 0         : Operation successful
- non-zero  : Operation failed
*/
int nt_crypto_end_security_context(sec_ctx_t);

/*
End all security context and stop the crypto library, all in-flight data is lost.

The function will return when all crypto resources has been closed and freed.
*/
int nt_crypto_end(void);


#endif /* _LIBCRYPTO_H_ */
