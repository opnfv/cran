#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_ring.h>			// fifo's
#include <rte_errno.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libcrypto.h"

// #include "zuc.h"


/* PDCP need the following cores: 1 x stat, 1 x libcrypt, min 1 x pdcp */
#define MIN_CORE_COUNT		(4)
#define MAX_CORE_COUNT		(8)

#define US_PER_SEC 			(1000000)

#define STAT_CORE_ID		(0)
#define LIBCRYPT_CORE_ID	(1)
#define DIST_CORE			(2)
#define FIRST_PDCP_CORE		(3)


/* Internal DPDK info */
#define PRIV_SIZE			(0)
#define MBUF_SIZE			(10000)
#define MBUF_CACHE_SIZE 	(250)
#define MBUF_COUNT 			(4096)

#define TX_QUEUE_ID			(0)
#define RX_QUEUE_ID			(0)

#define RX_RING_SIZE 		(1024)
#define TX_RING_SIZE 		(1024)

#define RX_BURST_SIZE		(16)

/* Batch memory management system */
#define IN_FIFO_SIZE 		(4096*2)
#define OUT_FIFO_SIZE 		(4096*2)
#define CALLBACK_FIFO_SIZE 	(4096*2)


/* .'.--.'. */

volatile uint8_t quit_signal;
static void int_handler(int sig_num) {
  printf("\nExiting on signal %d\n", sig_num);
  quit_signal = 1;
}


static int stat_print(void);
int init_pdcp(void);
int callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count);
int dist_worker(void *p);


/* System variables */

typedef struct {
	struct rte_mbuf 	*pkt;
	void 				*last_address;
} return_batch_s;


typedef struct {
	struct rte_ring 	*in_fifo;
	struct rte_ring    	*out_fifo;
	return_batch_s 		*current_return_batch;
} worker_s;

uint8_t 				worker_count;
worker_s 				workers[MAX_CORE_COUNT];

typedef struct {
	volatile uint64_t 	start_time;
	volatile uint64_t 	util_time;

	volatile uint64_t 	pkts_in;
	volatile uint64_t 	pkts_out;

	volatile uint64_t 	data_out;
	volatile uint64_t 	data_in;

} status_s;


volatile uint64_t 		init_time;

volatile status_s 		status[MAX_CORE_COUNT];

struct rte_mempool 	*mbuf_pool;

struct rte_ring 	*callback_fifo;


int init_pdcp(void) {

	int retval = 0;
	uint8_t pid;

	mbuf_pool = rte_pktmbuf_pool_create(	"MBUF_PDCP_POOL",
											MBUF_COUNT,
											MBUF_CACHE_SIZE,
											PRIV_SIZE,
											MBUF_SIZE + RTE_PKTMBUF_HEADROOM,
											rte_socket_id());

	if (NULL == mbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	struct ether_addr addr;

	const struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = ETHER_MAX_LEN,
			.split_hdr_size = 0,
			.header_split   = 0, /**< Header Split disabled */
			.hw_ip_checksum = 0, /**< IP checksum offload disabled */
			.hw_vlan_filter = 0, /**< VLAN filtering disabled */
			.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
			.hw_strip_crc   = 1, /**< CRC stripped by hardware */
		},
	};

	uint8_t nb_ports = rte_eth_dev_count();

	/* Initialize all ports. */
	for (pid = 0; pid < nb_ports; pid++){

		/* Get and display the port MAC address. */
		rte_eth_macaddr_get(pid, &addr);
		if(0xff == addr.addr_bytes[3]){
			// printf("Found libcrypto port at %d\n", pid);
			continue;
		}

		/* Configure the Ethernet device. */
		retval = rte_eth_dev_configure(pid, 1, 1, &port_conf);
		if (retval != 0) {
			rte_exit(EXIT_FAILURE, "Error in rte_eth_dev_configure\n");
			return retval;
		}

		retval = rte_eth_rx_queue_setup(pid, RX_QUEUE_ID, RX_RING_SIZE, rte_eth_dev_socket_id(pid), NULL, mbuf_pool);
		if (retval < 0){
			rte_exit(EXIT_FAILURE, "Error in rte_eth_rx_queue_setup\n");
			return retval;
		}

		retval = rte_eth_tx_queue_setup(pid, TX_QUEUE_ID, TX_RING_SIZE, rte_eth_dev_socket_id(pid), NULL);
		if (retval < 0){
			rte_exit(EXIT_FAILURE, "Error in rte_eth_tx_queue_setup\n");
			return retval;
		}

		/* Start the port. */
		retval = rte_eth_dev_start(pid);
		if (retval < 0){
			rte_exit(EXIT_FAILURE, "Error in rte_eth_dev_start\n");
			return retval;
		}

		printf("port %d has started\n", pid);
	}

	callback_fifo = rte_ring_create("callback_fifo_name", CALLBACK_FIFO_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (NULL == callback_fifo){
		printf("Error creating callback_fifo!\n");
		return -1;
	}

	return 0;
}


int callback(data_ctx_t data_ctx, data_out_t data_out[MAX_BURST_SIZE], uint16_t burst_count) {

	uint8_t tx_port_id = 0;

	int retval;
	void *fifo_return_data[1];
	uint64_t wid = (uint64_t)data_ctx;


	// printf("callback for worker %ld\n", wid);

	if (NULL == workers[wid].current_return_batch) {

		while (rte_ring_empty(workers[wid].out_fifo)){
			if ( unlikely(quit_signal) ) return 0;
		}

		retval = rte_ring_dequeue(workers[wid].out_fifo, fifo_return_data);
		if( unlikely(retval) ){
			rte_exit(EXIT_FAILURE, "Received batch with empty sequence FIFO !!!\n");
		}

		workers[wid].current_return_batch = (return_batch_s*)fifo_return_data[0];
	}

	// status[wid].pkts_out += burst_count;

	int i;
	for (i = 0; i < burst_count; ++i) {
		// status[wid].data_out += data_out[i].length;


		uint64_t *data = (uint64_t *)data_out[i].data;

		/* If the data is the last pkt in a batch, Tx it out now! */
		if( data == workers[wid].current_return_batch->last_address ){

			// printf("Last address found - Tx time!!\n");

			status[wid].pkts_out++;

			/* Restore the batch header from the buffer. */
			rte_pktmbuf_prepend(workers[wid].current_return_batch->pkt, sizeof(struct rte_mbuf_batch_pkt_hdr));


			/* Store the data return address on the queue. */
			while (rte_ring_full(callback_fifo)) {
				printf("callback_fifo is full!!!\n");
				if ( unlikely(quit_signal) ){
					return -1;
				}
			}
			retval = rte_ring_enqueue(callback_fifo, workers[wid].current_return_batch->pkt);
			if( unlikely(0 != retval) ){
				rte_exit(EXIT_FAILURE, "Error in rte_ring_enqueue into return_addr_fifo\n");
			}


			// uint16_t nb_tx = 0;
			// do {
			// 	if ( unlikely(quit_signal) ){
			// 		return -1;
			// 	}
			// 	nb_tx = rte_eth_tx_burst(tx_port_id, TX_QUEUE_ID, &workers[wid].current_return_batch->pkt, 1);
			// } while( unlikely(0 == nb_tx) );

			// rte_pktmbuf_free(workers[wid].current_return_batch->pkt);

			free(workers[wid].current_return_batch);

			/* Get the next return batch. */
			/*
				If the traffic stop, this point can deadlock the system.
				This loop will wait for new return batch, which will hold back all other sec_ctxs.
			*/
			while (rte_ring_empty(workers[wid].out_fifo)){

				if(i == burst_count - 1){
					// printf("Last batch wid: %d\n", wid);
					workers[wid].current_return_batch = NULL;
					return 0;
				}

				printf("No batch in fifo\n");
				if ( unlikely(quit_signal) ) return 0;
			}

			retval = rte_ring_dequeue(workers[wid].out_fifo, fifo_return_data);
			if( unlikely(retval) ){
				rte_exit(EXIT_FAILURE, "Received batch with empty sequence FIFO !!!\n");
			}

			workers[wid].current_return_batch = (return_batch_s*)fifo_return_data[0];
		}
	}

	return 0;
}


static int pdcp_worker(void *p) {
	uint64_t wid = (uint64_t)p;

	printf("Starting PDCP worker %ld\n", wid);

	int retval;

	struct rte_mbuf_batch_ctrl ctrl;
	struct rte_mbuf pkt;
	struct rte_mbuf *batch;

	void *work_dequeue[1];

	status[wid].start_time = 0;
	status[wid].util_time = 0;

	iv_t iv;

	symmetric_key_t 	sym_key;
	memset(sym_key, 0 , KEY_SIZE);


	char in_fifo_name[32];
 	snprintf(in_fifo_name, 32, "in_fifo_name_%ld", wid);
	workers[wid].in_fifo = rte_ring_create(in_fifo_name, IN_FIFO_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (NULL == workers[wid].in_fifo){
		printf("Error creating in_fifo for worker %ld!\n", wid);
		return -1;
	}

	char out_fifo_name[32];
 	snprintf(out_fifo_name, 32, "out_fifo_name_%ld", wid);
	workers[wid].out_fifo = rte_ring_create(out_fifo_name, OUT_FIFO_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (NULL == workers[wid].out_fifo){
		printf("Error creating out_fifo for worker %ld!\n", wid);
		return -1;
	}

	/* Initialise the current return batch to none. */
	workers[wid].current_return_batch = NULL;




	data_ctx_t data_ctx = (data_ctx_t)wid;
	sec_ctx_t sec_ctx = nt_crypto_new_security_context(LOOPBACK, sym_key, data_ctx);
	if(NULL == sec_ctx){
		printf("Error creating new security context!\n");
		return -1;
	}

 	while ( !quit_signal ) {

		// status[wid].start_time = rte_rdtsc();


		// printf("worker %ld looking for work\n", wid);

		 /* Wait for work in the queue.  */
		while (rte_ring_empty(workers[wid].in_fifo)){
			if ( unlikely(quit_signal) ) return 0;
		}

		retval = rte_ring_dequeue(workers[wid].in_fifo, work_dequeue);
		if( unlikely(retval) ){
			rte_exit(EXIT_FAILURE, "rte_ring_dequeue error\n");
		}
		batch = (struct rte_mbuf *)work_dequeue[0];

		// printf("worker %ld found work\n", wid);

		batch->ol_flags |= PKT_BATCH;

		return_batch_s *return_batch = malloc(sizeof(return_batch_s));

		/* Store the mbuf on the fifo, when it returns from libcrypto, it is send back. */
		return_batch->pkt = batch;

		/* Remove the batch header from the buffer. */
		rte_pktmbuf_adj(batch, sizeof(struct rte_mbuf_batch_pkt_hdr));
		batch->batch_size = batch->pkt_len;

		/* Store the data return address on the queue. */
		while (rte_ring_full(workers[wid].out_fifo)) {
			if ( unlikely(quit_signal) ){
				return -1;
			}
		}
		retval = rte_ring_enqueue(workers[wid].out_fifo, return_batch);
		if( unlikely(0 != retval) ){
			rte_exit(EXIT_FAILURE, "Error in rte_ring_enqueue into return_addr_fifo\n");
		}

		data_t	data;
		if (rte_pktmbuf_batch_get_first(batch, &pkt, &ctrl)) {
			do {
				// status[wid].data_in += pkt.data_len + 24;
				status[wid].data_in += pkt.data_len;
				status[wid].pkts_in++;

				data = rte_pktmbuf_mtod(&pkt, data_t);

				status[wid].start_time = rte_rdtsc();

				/* Copy the ciphertext directly back into the RX mbuf at the same position. */
				retval = nt_crypto_cipher(sec_ctx, &iv, data, data, pkt.data_len);
				if( unlikely(retval) ){
					printf("nt_crypto_cipher did not cipher!?!\n");
					quit_signal = 1;
					break;
				}

				status[wid].util_time += rte_rdtsc() - status[wid].start_time;

			} while (rte_pktmbuf_batch_get_next(batch, &pkt, &ctrl));

			/* Store the (last) data address of the batch => used to determine when a batch has returned. */
			return_batch->last_address = data;

		} // for each buffer
		// status[wid].util_time += rte_rdtsc() - status[wid].start_time;

	} // forever


	printf("Ending PDCP worker %ld\n", wid);
	return 0;
}

volatile uint32_t tx_count = 0;
volatile uint32_t try_counter = 0;

int dist_worker(void *p) {
	uint64_t wid = (uint64_t)p;

	printf("Starting DIST worker %ld\n", wid);

	int retval;
	uint8_t rx_port_id = 0;
	uint8_t tx_port_id = 0;

	uint8_t queue_id = 0;

	uint8_t current_worker = 0;

	void *tx_pkt_data[1];
	struct rte_mbuf * tx_batch;

	/* Ensure that all workers has started up! */
	// sleep(1);
	usleep(10000);

 	while ( !quit_signal ) {

		/* Get burst of RX packets, from first port of pair. */
		struct rte_mbuf *bufs[RX_BURST_SIZE];

		status[wid].start_time = rte_rdtsc();
		const uint32_t nb_rx = rte_eth_rx_burst(rx_port_id, queue_id, bufs, RX_BURST_SIZE);
		if (likely(nb_rx)) {

			uint16_t buf;
			for (buf = 0; buf < nb_rx; buf++) {


				// printf("Enqueue at worker %d\n", current_worker);
				while (rte_ring_full(workers[current_worker].in_fifo)) {
					if ( unlikely(quit_signal) ){
						printf("workers[current_worker].in_fifo is full: %d\n", current_worker);
						return -1;
					}
				}
				retval = rte_ring_enqueue( workers[current_worker].in_fifo, bufs[buf] );
				if( unlikely(0 != retval) ){
					rte_exit(EXIT_FAILURE, "Error in rte_ring_enqueue into return_addr_fifo\n");
				}

				current_worker = (current_worker + 1) % (worker_count - FIRST_PDCP_CORE);


				// status[wid].start_time = rte_rdtsc();
				// if( !rte_ring_empty(callback_fifo) ){

				// 	retval = rte_ring_dequeue(callback_fifo, tx_pkt_data);
				// 	if( unlikely(retval) ){
				// 		rte_exit(EXIT_FAILURE, "rte_ring_dequeue error\n");
				// 	}
				// 	tx_batch = (struct rte_mbuf *)tx_pkt_data[0];

				// 	uint16_t nb_tx = 0;
				// 	do {
				// 		if ( unlikely(quit_signal) ){
				// 			return -1;
				// 		}
				// 		nb_tx = rte_eth_tx_burst(tx_port_id, TX_QUEUE_ID, &tx_batch, 1);
				// 		try_counter++;
				// 	} while( unlikely(0 == nb_tx) );

				// 	tx_count++;

				// 	status[wid].util_time += (rte_rdtsc() - status[wid].start_time);
				// }


			}
		}

		// status[wid].util_time += rte_rdtsc() - status[wid].start_time;
		// status[wid].start_time = rte_rdtsc();

		int i;
		for(i = 0; i < 8; ++i){

			if(rte_ring_empty(callback_fifo) ){
				break;
			}

			// printf("dist_worker Tx time!\n");

			// status[wid].pkts_out++;

			retval = rte_ring_dequeue(callback_fifo, tx_pkt_data);
			if( unlikely(retval) ){
				rte_exit(EXIT_FAILURE, "rte_ring_dequeue error\n");
			}
			tx_batch = (struct rte_mbuf *)tx_pkt_data[0];



			// status[wid].start_time = rte_rdtsc();

			uint16_t nb_tx = 0;
			do {
				if ( unlikely(quit_signal) ){
					return -1;
				}
				nb_tx = rte_eth_tx_burst(tx_port_id, TX_QUEUE_ID, &tx_batch, 1);
			} while( unlikely(0 == nb_tx) );

			// status[wid].util_time += (rte_rdtsc() - status[wid].start_time);
		} /*for Tx batch. */

		status[wid].util_time += (rte_rdtsc() - status[wid].start_time);

	 } /* Forever */

	printf("Ending DIST worker %ld\n", wid);

	return 0;
}


int main(int argc, char *argv[]) {

	printf("Welcome to PDCP\n");

	uint8_t portid, worker_core, core;
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

	worker_count = rte_lcore_count();
	if ( MIN_CORE_COUNT > worker_count ) {
		printf("\nERROR: Need at least %i cores.\n", MIN_CORE_COUNT);
		return -1;
	}

	printf("Launching libcrypto worker on core: %d\n", LIBCRYPT_CORE_ID);
	ret = nt_crypto_init(callback, LIBCRYPT_CORE_ID);
	if(ret){
		printf("Error in nt_crypto_init\n");
		return -1;
	}

	ret = init_pdcp();

	// printf("Launching dist_worker worker on core: %d\n", DIST_CORE);
	rte_eal_remote_launch((lcore_function_t *)dist_worker, (void*)DIST_CORE, DIST_CORE);

	/* Start security contexts from the first free core - after the libcrypto thread. */
	for (worker_core = FIRST_PDCP_CORE; worker_core < worker_count; ++worker_core) {
		uint64_t idx = worker_core - FIRST_PDCP_CORE;
		// printf("Launching PDCP worker on core: %d\n", worker_core);
		rte_eal_remote_launch((lcore_function_t *)pdcp_worker, (void*)idx, worker_core);
		// rte_eal_remote_launch((lcore_function_t *)pdcp_worker, (void*)worker_core, worker_core);
		// usleep(10000);
	}

	stat_print();

	nt_crypto_end();


	RTE_LCORE_FOREACH_SLAVE(core) {
	if (rte_eal_wait_lcore(core) < 0)
		return -1;
	}

	uint8_t nb_ports = rte_eth_dev_count();
	for (portid = 0; portid < nb_ports; portid++) {
		printf("Closing port %i\n", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
	return 0;
}


static int stat_print(void) {

	uint64_t total_pkt_out = 0;
	uint64_t total_pkt_in;
	uint64_t prev_total_pkt_in = 0;

	uint64_t total_data_in;
	uint64_t prev_total_data_in = 0;

	uint64_t total_util_time = 0;

	init_time = rte_rdtsc();

	while ( !quit_signal ) {
		total_pkt_in = 0;
		total_data_in = 0;
		total_pkt_out = 0;

		total_util_time = 0;

		uint8_t i;
		for (i = 0; i < 2; ++i) {
			total_data_in += status[i].data_in;

			total_pkt_in += status[i].pkts_in;
			total_pkt_out += status[i].pkts_out;

			total_util_time += status[i].util_time;
			// printf("status[%d].util_time = %d\n", i , status[i].util_time/1000000000);
		}


		uint64_t byte_per_sec = total_data_in - prev_total_data_in;
		prev_total_data_in = total_data_in;
		double mbps = (byte_per_sec * 8 )  / 1000.0 / 1000.0;



		double mpps = (double)((total_pkt_in - prev_total_pkt_in) / 1000000.0);
		prev_total_pkt_in = total_pkt_in;

		double util = (double)total_util_time / (double)(rte_rdtsc() - init_time);
		double dist_util = (double)status[DIST_CORE].util_time / (double)(rte_rdtsc() - init_time);

		// printf("status[DIST_CORE].util_time = %0.2f\n", status[DIST_CORE].util_time / 1000000000.0);
		// printf("rte_rdtsc() - init_time = %0.2f\n", (rte_rdtsc() - init_time)/1000000000.0 ) ;

		printf("IN: %ld\tOUT: %ld\tinflight: %ld\tbw: %0.0f Mb/s\tmpps: %2.2f\tutil: %2.2f\tdutil: %2.2f\n", total_pkt_in, total_pkt_out, total_pkt_in - total_pkt_out, mbps, mpps, util, dist_util );
		sleep(1);
	}

  return 0;
}