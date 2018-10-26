#include "libcrypto.h"

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>			// struct rte_eth_conf
#include <rte_cycles.h>			// rte_get_timer_hz()
#include <rte_lcore.h>			// rte_pktmbuf_pool_create
#include <rte_ring.h>			// fifo's
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <rte_cryptodev.h>
#include <pthread.h>



#define NUM_MBUFS                       (8191)
#define MBUF_CACHE_SIZE                 (256)
#define MBUF_DATAPAYLOAD_SIZE		(2048 + DIGEST_BYTE_LENGTH_SHA512)
#define MBUF_SIZE			(sizeof(struct rte_mbuf) + \
		RTE_PKTMBUF_HEADROOM + MBUF_DATAPAYLOAD_SIZE)


#define BYTE_LENGTH(x)				(x/8)
#define DIGEST_BYTE_LENGTH_SHA512		(BYTE_LENGTH(512))

#define DEFAULT_NUM_XFORMS              (2)
#define MAX_BURST_SIZE                   (32)

#define RETURN_ADDR_FIFO_SIZE 	(8192*8)
#define SEQUENCE_FIFO_SIZE 		(8192*8)


#define IV_OFFSET		(sizeof(struct rte_crypto_op) + \
				sizeof(struct rte_crypto_sym_op))

#define TEST_HEXDUMP(file, title, buf, len) rte_hexdump(file, title, buf, len)


/*  Only support  EEA3 */
#define CONSTRUCT_IV(IV, COUNT, BEARER, DIRECTION)\
    do { \ 
	IV[0]	= (COUNT>>24) & 0xFF;\
	IV[1]	= (COUNT>>16) & 0xFF;\
	IV[2]	= (COUNT>>8)  & 0xFF;\
	IV[3]	=  COUNT      & 0xFF;\
	IV[4]	= ((BEARER << 3) | ((DIRECTION&1)<<2)) & 0xFC;\
    IV[5]	= 0;\
	IV[6]	= 0;\
	IV[7]	= 0;\
	IV[8]	= IV[0];\
	IV[9]	= IV[1];\
	IV[10]	= IV[2];\
	IV[11]	= IV[3];\
	IV[12]	= IV[4];\
	IV[13]	= IV[5];\
	IV[14]	= IV[6];\
	IV[15]	= IV[7];\
    } while(0)

#define CIPHER2WOKER_FIFO_SIZE 	(4096*2)


struct pkt_buffer {
    unsigned len;
    struct rte_mbuf *buffer[MAX_BURST_SIZE];
    data_out_t callback_data[MAX_BURST_SIZE];
};


#define RA_FIFO
typedef struct {
  symmetric_key_t 	key;
	struct rte_mbuf 	*mbuf;
#ifdef RA_FIFO
	struct rte_ring 	*return_addr_fifo;
#endif
	data_ctx_t 			data_ctx;
	uint16_t 			index;
	rte_spinlock_t 		lock;
	algo_type_t			type;
	uint64_t 			rx_count;
	uint64_t 			tx_count;
    struct pkt_buffer   pkt_buf;

/*qat*/
    struct rte_crypto_op *op[MAX_BURST_SIZE];
    struct rte_mbuf *ibuf[MAX_BURST_SIZE];
	struct rte_mbuf *obuf[MAX_BURST_SIZE];
    //uint16_t length[MAX_PKT_BURST];
    //data_t data_in[MAX_PKT_BURST];
    //data_t data_out[MAX_PKT_BURST];
    //unsigned datain_num;
} sec_ctx_s;





typedef struct
{
/////////////////////////////
    struct rte_mempool *mbuf_pool;
	struct rte_mempool *op_mpool;
	struct rte_mempool *session_mpool;
	struct rte_cryptodev_config conf;
	struct rte_cryptodev_qp_conf qp_conf;
	uint8_t valid_devs[RTE_CRYPTO_MAX_DEVS];
	uint8_t valid_dev_count;
//////////////////////////
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform aead_xform;
	struct rte_cryptodev_sym_session *sess;
    sec_ctx_s *sec_ctx_array[MAX_BURST_SIZE];
	struct pkt_buffer pkt_buf;
    uint8_t *digest;
    rte_spinlock_t queue_lock;
    long enqueue_sum;
    long dequeue_sum;
}nectar_ctx_s;

typedef struct {
    struct rte_mempool  *mbuf_pool;
	callback_t			__callback;
	uint64_t 			timeout_ticks;
	uint32_t 			sec_ctx_count;
	uint8_t 			crypto_port;
} crypto_ctx_s;


typedef struct {
	uint16_t data_original_len;
	data_t data_out;
    sec_ctx_s *sec_ctx;
}cipher2worker_ctx_s;

long count;

#if 0

#endif


static int gbl_driver_id;
volatile uint8_t 			running;
static crypto_ctx_s* 		crypto_ctx = NULL;
static nectar_ctx_s         nectar_ctx = { NULL };
static sec_ctx_s* g_sec_ctx;

static struct rte_ring 		*sequence_fifo;
rte_spinlock_t 				sequence_fifo_lock;

rte_spinlock_t 				new_sec_ctx_lock;

/*连接nt_crypto_cipher和nt_crypto_worker*/
struct rte_ring *cipher2worker;

static void print_stat(void) {

}


static void empty_inflight(void) {
	printf ("\nWaiting on inflights !!\n");

}

/*同步加密接口*/
static struct rte_crypto_op *
process_crypto_request(uint8_t dev_id, struct rte_crypto_op *op)
{
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		printf("Error sending packet for encryption");
		return NULL;
	}

	op = NULL;

	while (rte_cryptodev_dequeue_burst(dev_id, 0, &op, 1) == 0)
		rte_pause();
    //printf("xxxxxxxxxxxx op = %p\n", op);
	return op;
}

/*异步加密接口*/
static int process_crypto_request_async(uint8_t dev_id, struct rte_crypto_op *op)
{
	if (rte_cryptodev_enqueue_burst(dev_id, 0, &op, 1) != 1) {
		printf("Error sending packet for encryption\n");
		return -1;
	}

	return 0;
}


static int
create_wireless_algo_cipher_session(uint8_t dev_id,
			enum rte_crypto_cipher_operation op,
			enum rte_crypto_cipher_algorithm algo,
			const uint8_t *key, const uint8_t key_len,
			uint8_t iv_len)
{
	uint8_t cipher_key[key_len];

    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;

	memcpy(cipher_key, key, key_len);

	/* Setup Cipher Parameters */
	nectar_ctx_p->cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	nectar_ctx_p->cipher_xform.next = NULL;

	nectar_ctx_p->cipher_xform.cipher.algo = algo;
	nectar_ctx_p->cipher_xform.cipher.op = op;
	nectar_ctx_p->cipher_xform.cipher.key.data = cipher_key;
	nectar_ctx_p->cipher_xform.cipher.key.length = key_len;
	nectar_ctx_p->cipher_xform.cipher.iv.offset = IV_OFFSET;
	nectar_ctx_p->cipher_xform.cipher.iv.length = iv_len;

	/* Create Crypto session */
	nectar_ctx_p->sess = rte_cryptodev_sym_session_create(
			nectar_ctx_p->session_mpool);

	rte_cryptodev_sym_session_init(dev_id, nectar_ctx_p->sess,
			&nectar_ctx_p->cipher_xform, nectar_ctx_p->session_mpool);
	TEST_ASSERT_NOT_NULL(nectar_ctx_p->sess, "Session creation failed");
	return 0;
}


uint8_t session_is_create_flag = 0;
int create_session(sec_ctx_s* sec_ctx_ptr)
{
    sec_ctx_s *sec_ctx = sec_ctx_ptr;
    int retval;
    uint8_t dev_id;
    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;

    //g_sec_ctx = sec_ctx;

    dev_id = nectar_ctx_p->valid_devs[0];

    retval = create_wireless_algo_cipher_session(dev_id,
					RTE_CRYPTO_CIPHER_OP_ENCRYPT,
//                    RTE_CRYPTO_CIPHER_OP_DECRYPT,
					RTE_CRYPTO_CIPHER_ZUC_EEA3,
					sec_ctx->key, KEY_SIZE,
					MAXIMUM_IV_LENGTH);
	if (retval < 0)
		return retval;
}

static int
create_wireless_algo_cipher_operation(sec_ctx_s *sec_ctx, const uint8_t *iv, uint8_t iv_len,
			unsigned int cipher_len,
			unsigned int cipher_offset,
			int index)
{
    nectar_ctx_s *nectar_ctx_p = &nectar_ctx;
    unsigned datain_num;
    int i;

    i = index;

    /* Generate Crypto op data structure */
    sec_ctx->op[i] = rte_crypto_op_alloc(nectar_ctx_p->op_mpool,
			                                RTE_CRYPTO_OP_TYPE_SYMMETRIC);

    if(NULL == sec_ctx->op[i]) {
        printf("sec_ctx->op[%d] alloc error\n", i);
        return -1;
    }

    /* Set crypto operation data parameters */
    rte_crypto_op_attach_sym_session(sec_ctx->op[i], nectar_ctx_p->sess);

    struct rte_crypto_sym_op *sym_op = sec_ctx->op[i]->sym;
    /* set crypto operation source mbuf */
	sym_op->m_src = sec_ctx->ibuf[i];

    /* iv */
	rte_memcpy(rte_crypto_op_ctod_offset(sec_ctx->op[i], uint8_t *, IV_OFFSET),
			        iv, iv_len);
	sym_op->cipher.data.length = cipher_len;
	sym_op->cipher.data.offset = cipher_offset;

	return 0;

}
static uint32_t
ceil_byte_length(uint32_t num_bits)
{
	if (num_bits % 8)
		return ((num_bits >> 3) + 1);
	else
		return (num_bits >> 3);
}

uint8_t session_is_teardown_flag = 0;
void teardown_session()
{
    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;
    uint8_t dev_id = nectar_ctx_p->valid_devs[0];

    /* free crypto session structure */
    if(nectar_ctx_p->sess){
        rte_cryptodev_sym_session_clear(dev_id,
				nectar_ctx_p->sess);
		rte_cryptodev_sym_session_free(nectar_ctx_p->sess);
		nectar_ctx_p->sess = NULL;
    }
    session_is_teardown_flag = 1;
}

//int crypto_send_messages(sec_ctx_s *sec_ctx, struct rte_mbuf *m)
int crypto_send_messages(sec_ctx_s *sec_ctx, void* data_out, uint16_t crypto_data_len)
{
	nectar_ctx_s * nectar_ctx_p = &nectar_ctx;
	unsigned len;
	//struct rte_mbuf **pkt_buffer;
	int ret;
    data_out_t *callback_data;
    int j;

    if(0 == data_out) {
        printf("crypto_send_messages error: m is NULL.\n");
        return -1;
    }

	len = sec_ctx->pkt_buf.len;
	//pkt_buffer = sec_ctx->pkt_buf.buffer;
    callback_data = sec_ctx->pkt_buf.callback_data;
    callback_data[len].data = data_out;
    callback_data[len].length = crypto_data_len;

	//pkt_buffer[len] = m;
	len++;
	
	if(MAX_BURST_SIZE == len) {

        ret = crypto_ctx->__callback(sec_ctx->data_ctx, callback_data, MAX_BURST_SIZE);
        if(ret < 0) {
            //printf("callback failed.\n");
        }

		len = 0;
	}

	sec_ctx->pkt_buf.len = len;
} 


int nt_crypto_cipher(sec_ctx_t sec_ctx_ptr, iv_t *iv, cipher_input *crypto_input, uint16_t nb_cipher){
    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;

	int retval, dev_id;
	uint8_t *plaintext, *ciphertext;
	unsigned plaintext_pad_len;
	unsigned plaintext_len;
    cipher2worker_ctx_s *cipher2worker_data;
    unsigned datain_num;
    unsigned ret, ret2;
    unsigned nb_result;
    unsigned nb_result_sum;
    int j;
    struct rte_mbuf *m;
    //struct rte_mbuf *bufs_crypto[MAX_PKT_BURST] = {0};      /////////////////
	struct rte_cryptodev_sym_capability_idx cap_idx;

	if( unlikely(0    == running) 		){ printf("Error in nt_crypto_cipher: libcrypto not running\n");	return 0; }
	if( unlikely(NULL == sec_ctx_ptr) 	){ printf("Error in nt_crypto_cipher: sec_ctx is null\n"); 			return 0; }
	if( unlikely(NULL == iv) 			){ printf("Error in nt_crypto_cipher: iv is null\n"); 				return 0; }
	if( unlikely(0    == nb_cipher) 	){ printf("Zero length - do nothing\n"); 						    return  0; }

    for(j=0; j<nb_cipher; j++) {
        if((crypto_input[j].data_in == NULL) || (crypto_input[j].data_out == NULL) || (crypto_input[j].length == 0)) {
            printf("data_in[%d] error\n", j);
            printf("data_in[%d].data_in=%p\n", crypto_input[j].data_in);
            printf("data_in[%d].data_out=%p\n", crypto_input[j].data_out);
            printf("data_in[%d].length=%p\n", crypto_input[j].length);
            return 0;
        }        
    }
    
	sec_ctx_s *sec_ctx = (sec_ctx_s*)sec_ctx_ptr;

    for(j=0; j<nb_cipher; j++) {
        sec_ctx->ibuf[j] = rte_pktmbuf_alloc(nectar_ctx_p->mbuf_pool);
        if(NULL == sec_ctx->ibuf[j]) {
            printf("sec_ctx->ibuf[%d] is NULL\n", j);
            goto err1;
        }
        /* Clear mbuf payload */
        memset(rte_pktmbuf_mtod(sec_ctx->ibuf[j], uint8_t *), 0,
                rte_pktmbuf_tailroom(sec_ctx->ibuf[j]));
    }
    
	/* Check if device supports ZUC EEA3 */
	cap_idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cap_idx.algo.cipher = RTE_CRYPTO_CIPHER_ZUC_EEA3;
    dev_id = nectar_ctx_p->valid_devs[0];
    
	if (rte_cryptodev_sym_capability_get(dev_id, &cap_idx) == NULL)
		goto err1;

    uint32_t COUNT = iv->counter;
    uint32_t BEARER = iv->bearer & 0x1F;
    uint32_t DIRECTION = iv->direction & 0x1;
    
	uint8_t 	IV[16];
    CONSTRUCT_IV(IV, COUNT, BEARER, DIRECTION);

    //datain_num = sec_ctx->datain_num;

    for(j=0; j<nb_cipher; j++) {
        //sec_ctx->length[j] = crypto_input[j]->length;
        //sec_ctx->data_in[j] = crypto_input[j]->data_in;
        //sec_ctx->data_out[j] = crypto_input[j]->data_out;

        
        plaintext_len = crypto_input[j].length;
        /* Append data which is padded to a multiple */
        /* of the algorithms block size */
        plaintext_pad_len = RTE_ALIGN_CEIL(plaintext_len, 8);
        plaintext = (uint8_t *)rte_pktmbuf_append(sec_ctx->ibuf[j], plaintext_pad_len);
        if(NULL == plaintext) {
            
        }
        /*把待加密内容拷贝到新分配的mbuf里*/
        memcpy(plaintext, crypto_input[j].data_in, plaintext_len);

        /* Create ZUC operation */
        /* use bit length of plaintext */
        retval = create_wireless_algo_cipher_operation(sec_ctx, &IV[0], 
                                                        MAXIMUM_IV_LENGTH, plaintext_len * 8, 
                                                        0, j);
        if (retval < 0) {
            goto err2;
        }
    }

	/*加保护*/
	rte_spinlock_lock(&nectar_ctx_p->queue_lock);
    ret = rte_cryptodev_enqueue_burst(dev_id, 0, sec_ctx->op, nb_cipher);
	ret2 = ret;
	if (unlikely(ret2 < nb_cipher)) {
		//printf("rte_cryptodev_enqueue_burst has %d failed\n", MAX_PKT_BURST - ret2);
		do {
			rte_pktmbuf_free(sec_ctx->op[ret2]->sym->m_src);
			rte_crypto_op_free(sec_ctx->op[ret2]);
		} while (++ret2 < nb_cipher);
	}

    for(j=0; j<ret; j++) {
        while (rte_ring_full(cipher2worker)){
			/* If crypto was shutdown while waiting.*/
			if (unlikely(0 == running)){
				rte_spinlock_unlock(&nectar_ctx_p->queue_lock);
				return 0;
			}
		}

        /*申请填充cipher2worker_data，并把cipher2worker_data送入队列*/
        cipher2worker_data = malloc(sizeof(cipher2worker_ctx_s));
        cipher2worker_data->data_original_len = crypto_input[j].length;
        cipher2worker_data->data_out = crypto_input[j].data_out;
        cipher2worker_data->sec_ctx = sec_ctx;

        retval = rte_ring_enqueue(cipher2worker, cipher2worker_data);
        if(retval < 0) {
            free(cipher2worker_data);
			rte_exit(EXIT_FAILURE, "sequence_fifo is error\n");
            continue;
		}
        
        //TEST_HEXDUMP(stdout, "data_original[j]:", data_original[j], data_original_len);
	}

    nectar_ctx_p->enqueue_sum = ret;
    rte_spinlock_unlock(&nectar_ctx_p->queue_lock);

    return ret;
    
err2:
    for(j=0; j<nb_cipher; j++) {
        if(NULL != sec_ctx->op[j]) {
            rte_crypto_op_free(sec_ctx->op[j]);
        }
    }
err1:
    for(j=0; j<nb_cipher; j++) {
        if(NULL != sec_ctx->ibuf[j]) {
            rte_pktmbuf_free(sec_ctx->ibuf[j]);
            sec_ctx->ibuf[j] = NULL;
        } 
    }

    rte_spinlock_unlock(&nectar_ctx_p->queue_lock);
    
	return 0;
}


void nt_crypto_worker(void)
{
    int nb_result;
    data_t data_out;
    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;
    struct rte_crypto_op *op;
    unsigned int nb_ciphertext;
    uint8_t *ciphertext;
    uint8_t dev_id = nectar_ctx_p->valid_devs[0];
    cipher2worker_ctx_s *cipher2worker_data;
    //sec_ctx_s *sec_ctx;
    struct rte_crypto_op *ops_burst[MAX_BURST_SIZE];
    struct rte_mbuf *tx_batch;
    int j;
    int retval;
    sec_ctx_s *sec_ctx;
    uint16_t crypto_data_len;

    printf("Starting  nt_crypto_worker\n");

    while(likely(running)) {

        /* Dequeue packets from Crypto device */
        rte_spinlock_lock(&nectar_ctx_p->queue_lock);
        nb_result = rte_cryptodev_dequeue_burst(dev_id, 0, ops_burst, MAX_BURST_SIZE);
        
        /* Forward crypto'd packets */
        for (j = 0; j < nb_result; j++) {
            tx_batch = ops_burst[j]->sym->m_src;
            if(0 == tx_batch) {
                printf("nt_crypto_worker error: tx_batch is NULL.\n");
            }

            retval = rte_ring_dequeue(cipher2worker, (void **)&cipher2worker_data);
			if(retval < 0) {
				printf("rte_ring_dequeue is error\n");
            }

            
            crypto_data_len = cipher2worker_data->data_original_len;
            ciphertext = cipher2worker_data->data_out;
            sec_ctx = cipher2worker_data->sec_ctx;
            memcpy(ciphertext, rte_pktmbuf_mtod(tx_batch, void *), crypto_data_len);
            //TEST_HEXDUMP(stdout, "fifo_return_data[0]:", fifo_return_data[0], rte_pktmbuf_data_len(tx_batch));

            rte_crypto_op_free(ops_burst[j]);
            rte_pktmbuf_free(tx_batch);
            free(cipher2worker_data);
            crypto_send_messages(sec_ctx, ciphertext, crypto_data_len);
        }
        
        nectar_ctx_p->dequeue_sum += nb_result;
        rte_spinlock_unlock(&nectar_ctx_p->queue_lock);
    }

    printf("nt_crypto_worker exit\n");

}

sec_ctx_t nt_crypto_new_security_context(algo_type_t algo_type, symmetric_key_t key, data_ctx_t data_ctx) {
	if(NULL == crypto_ctx){
		printf("Error: nectar libcrypto not running\n");
		return NULL;
	}

	rte_spinlock_lock(&new_sec_ctx_lock);

	if(MAX_SEC_CTX <= crypto_ctx->sec_ctx_count){
		printf("Error reached max security context count.\n");
		rte_spinlock_unlock(&new_sec_ctx_lock);
		return NULL;
	}

    /*应该用不到*/
	//int idx = 0;
	//for (; idx < MAX_SEC_CTX; ++idx) {
	//	if( TIMEOUT_FREE == timeout[idx] ){
			/* Reserve the idx by removing TIMEOUT_FREE. */
	//		timeout[idx] = TIMEOUT_DISABLED;
	//		break;
	//	}
	//}

	/* Create a new security context. */
	sec_ctx_s* sec_ctx = (sec_ctx_s*)malloc(sizeof(sec_ctx_s));
	if(NULL == sec_ctx){
		printf("Error allocating memory for security context!\n");
		goto fail_new_sec_ctx;
	}
    memset(sec_ctx, 0, sizeof(sec_ctx_s));
    printf("sec_ctx=%p\n", sec_ctx);

    //g_sec_ctx = sec_ctx;

	/* Install the encryption key in the security context. */
	memcpy(sec_ctx->key, key, KEY_SIZE);

	/* Save the data_context for the new security context. */
	sec_ctx->data_ctx = data_ctx;

    /*应该用不到sec_ctx->mbuf */
    //sec_ctx->mbuf = rte_pktmbuf_alloc(crypto_ctx->mbuf_pool);
	//if(NULL == sec_ctx->mbuf){
	//	printf("Error allocating mbuf for security context!\n");
	//	goto fail_new_sec_ctx_free;
	//}
	//sec_ctx->mbuf->pkt_len = 0;

    /*是否需要fifo?*/
    char sec_ctx_name[32];
 	snprintf(sec_ctx_name, 32, "sec_ctx_return_fifo_%d", crypto_ctx->sec_ctx_count);
	sec_ctx->return_addr_fifo = rte_ring_create(sec_ctx_name, RETURN_ADDR_FIFO_SIZE, SOCKET_ID_ANY, 0);
	if (NULL == sec_ctx->return_addr_fifo) {
		printf("Error in rte_ring_create!\n");
		goto fail_new_sec_ctx;
	}
    crypto_ctx->sec_ctx_count++;

    
    sec_ctx->type = algo_type;

    if(0 == session_is_create_flag) {
        create_session(sec_ctx);
        session_is_create_flag = 1;
    }
    rte_spinlock_unlock(&new_sec_ctx_lock);
    
	return (sec_ctx_t)sec_ctx;

fail_new_sec_ctx:
	rte_spinlock_unlock(&new_sec_ctx_lock);

	return NULL;
}

/*

Stop the security context:

- must not be able to encrypt more data.

- packets in the batch should be destroyed.
- packets received should be ?destroyed? or ?called back?

- sec_ctx mbuf must be free.

- the sec_ctx_collection index must be NULLed.
- the timeout must be disabled before return.

*/
int nt_crypto_end_security_context(sec_ctx_t sec_ctx_ptr) {

	if(NULL == crypto_ctx)	{	printf("Error: Nectar libcrypto not running\n");	return -1;	}
	if(NULL == sec_ctx_ptr)	{ 	printf("Error: Nectar sec_ctx is null\n"); 		return -1; 	}

    sec_ctx_s* sec_ctx = (sec_ctx_s*)sec_ctx_ptr;

    rte_ring_free(sec_ctx->return_addr_fifo);
    
    free(sec_ctx_ptr);
    
    if(0 == session_is_teardown_flag)
        teardown_session();
    
	return -1;
}

static int initialize_cryptodevs(unsigned int core)
{
// TODO:
	unsigned int session_size;
    nectar_ctx_s * nectar_ctx_p = &nectar_ctx;

    struct rte_cryptodev_info info;
	uint32_t i = 0, nb_devs, dev_id;
	uint16_t qp_id;
    int retval;
    struct rte_mbuf* buf;

	memset(nectar_ctx_p, 0, sizeof(*nectar_ctx_p));

	nectar_ctx_p->mbuf_pool = rte_mempool_lookup("CRYPTO_MBUFPOOL");
	if (nectar_ctx_p->mbuf_pool == NULL) {
		/* Not already created so create */
		nectar_ctx_p->mbuf_pool = rte_pktmbuf_pool_create(
				"CRYPTO_MBUFPOOL",
				NUM_MBUFS, MBUF_CACHE_SIZE, 0, MBUF_SIZE,
				rte_socket_id());
		if (nectar_ctx_p->mbuf_pool == NULL) {
			RTE_LOG(ERR, USER1, "Nectar:Can't create CRYPTO_MBUFPOOL\n");
			return -1;
		}
	}

	nectar_ctx_p->op_mpool = rte_crypto_op_pool_create(
			"MBUF_CRYPTO_SYM_OP_POOL",
			RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			NUM_MBUFS, MBUF_CACHE_SIZE,
			DEFAULT_NUM_XFORMS *
			sizeof(struct rte_crypto_sym_xform) +
			MAXIMUM_IV_LENGTH,
			rte_socket_id());
	if (nectar_ctx_p->op_mpool == NULL) {
		RTE_LOG(ERR, USER1, "Nectar: Can't create CRYPTO_OP_POOL\n");
		return -1;
	}

	gbl_driver_id =	rte_cryptodev_driver_id_get(
			RTE_STR(CRYPTODEV_NAME_QAT_SYM_PMD));

	if (gbl_driver_id == -1) {
		RTE_LOG(ERR, USER1, "Nectar: QAT PMD must be loaded. Check if "
				"CONFIG_RTE_LIBRTE_PMD_QAT is enabled "
				"in config file to run this testsuite.\n");
		return -1;
	}

	nb_devs = rte_cryptodev_count();
	if (nb_devs < 1) {
		RTE_LOG(ERR, USER1, "Nectar: No crypto devices found?\n");
		return -1;
	}

	/* Create list of valid crypto devs */
	for (i = 0; i < nb_devs; i++) {
		rte_cryptodev_info_get(i, &info);
		if (info.driver_id == gbl_driver_id)
			nectar_ctx_p->valid_devs[nectar_ctx_p->valid_dev_count++] = i;
	}

	if (nectar_ctx_p->valid_dev_count < 1)
		return -1;

	dev_id = nectar_ctx_p->valid_devs[0];

	rte_cryptodev_info_get(dev_id, &info);

	nectar_ctx_p->conf.nb_queue_pairs = info.max_nb_queue_pairs;
	nectar_ctx_p->conf.socket_id = SOCKET_ID_ANY;
	
    session_size = rte_cryptodev_get_private_session_size(dev_id);

	/*
	 * Create mempool with maximum number of sessions * 2,
	 * to include the session headers
	 */
	nectar_ctx_p->session_mpool = rte_mempool_create(
				"test_sess_mp",
				info.sym.max_nb_sessions * 2,
				session_size,
				0, 0, NULL, NULL, NULL,
				NULL, SOCKET_ID_ANY,
				0);

	rte_cryptodev_configure(dev_id, &nectar_ctx_p->conf),

	nectar_ctx_p->qp_conf.nb_descriptors = DEFAULT_NUM_OPS_INFLIGHT;

	for (qp_id = 0; qp_id < info.max_nb_queue_pairs; qp_id++) {
		rte_cryptodev_queue_pair_setup(
			dev_id, qp_id, &nectar_ctx_p->qp_conf,
			rte_cryptodev_socket_id(dev_id),
			nectar_ctx_p->session_mpool);
	}

	/* Cronstruct the batch return sequence fifo. */
	//sequence_fifo = rte_ring_create("sequence_fifo", SEQUENCE_FIFO_SIZE, SOCKET_ID_ANY, 0);
	//if (NULL == sequence_fifo)
	//	rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));


    cipher2worker = rte_ring_create("cipher2worker_fifo_name", CIPHER2WOKER_FIFO_SIZE, SOCKET_ID_ANY, 0);
	if (NULL == cipher2worker){
		printf("Error creating cipher2worker_fifo!\n");
		return -1;
	}
#if 0

#endif

    /*对锁进行初始化*/
    rte_spinlock_init(&nectar_ctx_p->queue_lock);

//	memset(nectar_ctx_p, 0, sizeof(*nectar_ctx_p));
	/* Start the device */
	rte_cryptodev_start(nectar_ctx_p->valid_devs[0]);

    running = 1;

    /* 创建线程从qat取加密结果*/
	retval = rte_eal_remote_launch((lcore_function_t *)nt_crypto_worker, NULL, core);
	if (retval < 0){
		rte_exit(EXIT_FAILURE, "Error in rte_eal_remote_launch\n");
		return retval;
	}  


    return 0;
}

int nt_crypto_init(callback_t callback, uint8_t core){
    int retval;
    
    running = 0;

    if(NULL != crypto_ctx){
        printf("Error: libcrypto is already running\n");
        return -1;
    }

    if(NULL == callback)
        rte_exit(EXIT_FAILURE, "Error callback is NULL!\n");

    /* Create a new nectar crypto context. */
    crypto_ctx = (crypto_ctx_s*)malloc(sizeof(crypto_ctx_s));
    if(NULL == crypto_ctx)
        rte_exit(EXIT_FAILURE, "Error allocating memory for nectar crypto context!\n");
    memset(crypto_ctx, 0, sizeof(crypto_ctx_s));

    /* Install the callback function. */
    crypto_ctx->__callback = callback;

    retval = initialize_cryptodevs(core);
    if(retval < 0) {
        RTE_LOG(ERR, USER1, "Nectar: initialize_cryptodevs failed.\n");
        return -1;
    }
    rte_spinlock_init(&new_sec_ctx_lock);
  
	printf("Nectar crypto init ok!\n");
	return 0;
}


int nt_crypto_end(void){
	if(0 == running || NULL == crypto_ctx){
		// printf("Error: libcrypto not running\n");
		return -1;
	}

	running = 0;

	/* Give all parth of the library a chance to do work and shutdown. */
	sleep(1);

	empty_inflight();

	print_stat();

	free(crypto_ctx);
	crypto_ctx = NULL;

	printf("Nectar crypto has ended!\n");
    return 0;
}

