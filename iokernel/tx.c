/*
 * tx.c - the transmission path for the I/O kernel (runtimes -> network)
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>

#include <base/log.h>
#include <net/udp.h>
#include <iokernel/queue.h>

#include "defs.h"
#include "base/byteorder.h"

#include <signal.h>
#include <stdio.h>

#define TX_PREFETCH_STRIDE 2
#define TX_MAX_SEGS (IOKERNEL_TX_BURST_SIZE * 64)
#define UDP_OFFSET 34

unsigned int nrts;
struct thread *ts[NCPU];

static struct rte_mempool *tx_mbuf_pool;

/*
 * Private data stored in egress mbufs, used to send completions to runtimes.
 */
struct tx_pktmbuf_priv {
#ifdef MLX
	uint32_t lkey;
#endif /* MLX */
	struct proc	*p;
	struct thread	*th;
	unsigned long	completion_data;
};

static inline struct tx_pktmbuf_priv *tx_pktmbuf_get_priv(struct rte_mbuf *buf)
{
	return (struct tx_pktmbuf_priv *)(((char *)buf)
			+ sizeof(struct rte_mbuf));
}

/*
 * Prepare rte_mbuf struct for transmission.
 */
static void tx_prepare_tx_mbuf(struct rte_mbuf *buf,
			       const struct tx_net_hdr *net_hdr,
			       struct thread *th)
{
	struct proc *p = th->p;
	uint32_t page_number;
	struct tx_pktmbuf_priv *priv_data;

	/* initialize mbuf to point to net_hdr->payload */
	buf->buf_addr = (char *)net_hdr->payload;
	page_number = PGN_2MB((uintptr_t)buf->buf_addr - (uintptr_t)p->region.base);
	buf->buf_physaddr = p->page_paddrs[page_number] + PGOFF_2MB(buf->buf_addr);
	buf->data_off = 0;
	rte_mbuf_refcnt_set(buf, 1);

	buf->buf_len = net_hdr->len;
	buf->pkt_len = net_hdr->len;
	buf->data_len = net_hdr->len;

	buf->ol_flags = 0;
	if (net_hdr->olflags != 0) {
		if (net_hdr->olflags & OLFLAG_IP_CHKSUM)
			buf->ol_flags |= PKT_TX_IP_CKSUM;
		if (net_hdr->olflags & OLFLAG_TCP_CHKSUM)
			buf->ol_flags |= PKT_TX_TCP_CKSUM;
		if (net_hdr->olflags & OLFLAG_IPV4)
			buf->ol_flags |= PKT_TX_IPV4;
		if (net_hdr->olflags & OLFLAG_IPV6)
			buf->ol_flags |= PKT_TX_IPV6;

		buf->l4_len = sizeof(struct rte_tcp_hdr);
		buf->l3_len = sizeof(struct rte_ipv4_hdr);
		buf->l2_len = RTE_ETHER_HDR_LEN;
	}

	/* initialize the private data, used to send completion events */
	priv_data = tx_pktmbuf_get_priv(buf);
	priv_data->p = p;
	priv_data->th = th;
	priv_data->completion_data = net_hdr->completion_data;

#ifdef MLX
	/* initialize private data used by Mellanox driver to register memory */
	priv_data->lkey = p->lkey;
#endif /* MLX */

	/* reference count @p so it doesn't get freed before the completion */
	proc_get(p);
}

/*
 * Send a completion event to the runtime for the mbuf pointed to by obj.
 */
bool tx_send_completion(void *obj)
{
	struct rte_mbuf *buf;
	struct tx_pktmbuf_priv *priv_data;
	struct thread *th;
	struct proc *p;

	buf = (struct rte_mbuf *)obj;
	priv_data = tx_pktmbuf_get_priv(buf);
	p = priv_data->p;

	/* during initialization, the mbufs are enqueued for the first time */
	if (unlikely(!p))
		return true;

	/* check if runtime is still registered */
	if(unlikely(p->kill)) {
		proc_put(p);
		return true; /* no need to send a completion */
	}

	/* no need to send completion event for all segments except the last one */
	if (likely(priv_data->completion_data == 0)) {
		proc_put(p);
		return true;
	}

	/* send completion to runtime */
	th = priv_data->th;
	if (th->active) {
		if (likely(lrpc_send(&th->rxq, RX_NET_COMPLETE,
			       priv_data->completion_data))) {
			goto success;
		}
	} else {
		if (likely(rx_send_to_runtime(p, p->next_thread_rr++, RX_NET_COMPLETE,
					priv_data->completion_data))) {
			goto success;
		}
	}

	if (unlikely(p->nr_overflows == p->max_overflows)) {
		log_warn("tx: Completion overflow queue is full");
		return false;
	}
	p->overflow_queue[p->nr_overflows++] = priv_data->completion_data;
	log_debug_ratelimited("tx: failed to send completion to runtime");
	STAT_INC(COMPLETION_ENQUEUED, -1);
	STAT_INC(TX_COMPLETION_OVERFLOW, 1);


success:
	proc_put(p);
	STAT_INC(COMPLETION_ENQUEUED, 1);
	return true;
}

static int drain_overflow_queue(struct proc *p, int n)
{
	int i = 0;
	while (p->nr_overflows > 0 && i < n) {
		log_info("draining overflow queue");
		if (!rx_send_to_runtime(p, p->next_thread_rr++, RX_NET_COMPLETE,
				p->overflow_queue[--p->nr_overflows])) {
			p->nr_overflows++;
			break;
		}
		i++;
	}
	return i;
}

bool tx_drain_completions(void)
{
	static unsigned long pos = 0;
	unsigned long i;
	size_t drained = 0;
	struct proc *p;

	for (i = 0; i < dp.nr_clients && drained < IOKERNEL_OVERFLOW_BATCH_DRAIN; i++) {
		p = dp.clients[(pos + i) % dp.nr_clients];
		drained += drain_overflow_queue(p, IOKERNEL_OVERFLOW_BATCH_DRAIN - drained);
	}

	pos++;

	STAT_INC(COMPLETION_DRAINED, drained);

	return drained > 0;

}

static int tx_drain_queue(struct thread *t, int n, struct tx_net_hdr **hdrs)
{
	int i;

	for (i = 0; i < n; i++) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&t->txpktq, &cmd, &payload)) {
			if (unlikely(!t->active))
				unpoll_thread(t);
			break;
		}

		/* TODO: need to kill the process? */
		BUG_ON(cmd != TXPKT_NET_XMIT);

		hdrs[i] = shmptr_to_ptr(&t->p->region, payload,
					sizeof(struct tx_net_hdr));
		/* TODO: need to kill the process? */
		BUG_ON(!hdrs[i]);
	}

	return i;
}


/*
 * Process a batch of outgoing packets.
 */
bool tx_burst(void)
{
	struct tx_net_hdr *hdrs[IOKERNEL_TX_BURST_SIZE];
	struct thread *threads[IOKERNEL_TX_BURST_SIZE];
	unsigned int i, j, ret, pulltotal = 0;
	static unsigned int pos = 0, n_pkts = 0, n_bufs = 0;
	struct thread *t;

	/*
	 * Poll each kthread in each runtime until all have been polled or we
	 * have PKT_BURST_SIZE pkts.
	 */
	for (i = 0; i < nrts; i++) {
		unsigned int idx = (pos + i) % nrts;
		t = ts[idx];
		ret = tx_drain_queue(t, IOKERNEL_TX_BURST_SIZE - n_pkts,
				     &hdrs[n_pkts]);
		for (j = n_pkts; j < n_pkts + ret; j++)
			threads[j] = t;
		n_pkts += ret;
		pulltotal += ret;
		if (n_pkts >= IOKERNEL_TX_BURST_SIZE)
			goto full;
	}

	if (n_pkts == 0)
		return false;

	pos++;

full:

	stats[TX_PULLED] += pulltotal;

	/* UDP GSO */
	char *chunk, *chunk_cm, *dest;
	unsigned int data_len, segs, m;
	unsigned long pkt_len;
	struct udp_hdr *udp_hdr;
	struct tx_net_hdr *shdr;
	struct thread *seg_ts[TX_MAX_SEGS];
	const struct tx_net_hdr *seg_hdrs[TX_MAX_SEGS];
	static struct rte_mbuf *bufs[TX_MAX_SEGS];
	struct cipher_meta *cm;

	m = n_bufs;  // number of segmented packets.
	for (i = n_bufs; i < n_pkts; ++i) {
		/* Filter non-cipher packets. */
		if (!hdrs[i]->pad) {
			seg_ts[m] = threads[i];
			seg_hdrs[m++] = hdrs[i];
			continue;
		}

		/* Get the number of segments (segs) & data length (data_len).
		 * We have:
		 * hdrs[i]->len + 18 = 60 * segs + 41 * segs + data_len + 16 * segs
		 * where,
		 * tx_net_hdr + eth_hdr + ip_hdr + udp_hdr = 60
		 * & CIPHER_META_SZ = 41
		 * & CIPHER_OVERHEAD = 16
		 */
		udp_hdr = (struct udp_hdr *) (hdrs[i]->payload + UDP_OFFSET);
		data_len = ntoh16(udp_hdr->len) - 8;
		segs = hdrs[i]->len + 18 - data_len;
		segs /= 60 + CIPHER_META_SZ + CIPHER_OVERHEAD;

		/* Get the pointer to the end of data */
		chunk = hdrs[i]->payload + 42 + CIPHER_META_SZ * segs;
		chunk += data_len;

		/* Get the cipher meta for the last chunk */
		chunk_cm = hdrs[i]->payload + 42 + CIPHER_META_SZ * (segs - 1);

#if 0
		if (segs == 2) {
			log_info("Before processing:");
			for (int p = 0; p < (hdrs[i]->len + 18); ++p) {
				printf("%02x ", *((uint8_t *) (hdrs[i] + p)));
				if (p % 64 == 63) printf("\n");
			}
			log_info("Done");
		}
#endif

		/* Perform encryption & memory ops, begin from the last chunk */
		for (j = 1; j <= segs; ++j) {
			/* Consider the (chunk_len)-byte chunk at curr. */
			cm = (struct cipher_meta *) (chunk_cm);
			pkt_len = cm->header_len + cm->body_len + CIPHER_OVERHEAD;
			chunk -= pkt_len - CIPHER_OVERHEAD;

			CiphersC_inplace_encrypt(
				cips,
				cm->aead_index,
				cm->packet_num,
				chunk,
				cm->header_len,
				chunk + cm->header_len,
				cm->body_len + CIPHER_OVERHEAD);

			CiphersC_encrypt_packet_header(
				cips,
				cm->header_cipher_index,
				cm->header_form,
				chunk,
				cm->header_len,
				chunk + cm->header_len,
				cm->body_len + CIPHER_OVERHEAD);

#if 0
			if (segs == 2) {
				for (int p = 0; p < (hdrs[i]->len + 18); ++p) {
					printf("%02x ", *((uint8_t *) (hdrs[i] + p)));
					if (p % 64 == 63) printf("\n");
				}
				log_info("Done");
			}
#endif

			dest = chunk;
			dest += (segs - j) * 60;
			dest += (segs - j) * CIPHER_OVERHEAD;

			/* chunk has expanded by CIPHER_OVERHEAD */
			if (dest != chunk)
				memmove(dest, chunk, pkt_len);

			/* Perform memory moves for headers.
			 * "memmove" since dest and src may overlap.
			 * This may corrupt cm (for first chunk). Do not use cm below. */
			dest -= 60;
			memmove(dest, hdrs[i], 60);

#if 0
			if (segs == 2) {
				log_info("After processing j = %d (from last)", j);
				for (int p = 0; p < (hdrs[i]->len + 18); ++p) {
					printf("%02x ", *((uint8_t *) (hdrs[i] + p)));
					if (p % 64 == 63) printf("\n");
				}
				log_info("Done");
			}
#endif

			/* Update tx_net_hdr, udp_hdr, ip_hdr len fields. */
			shdr = (struct tx_net_hdr *) dest;
			shdr->len = 42 + pkt_len;
			if (j > 1) shdr->completion_data = 0;
			*(uint16_t *)(shdr->payload + 38) = hton16(shdr->len - 34);
			*(uint16_t *)(shdr->payload + 16) = hton16(shdr->len - 14);

			seg_ts[m+segs-j] = threads[i];
			seg_hdrs[m+segs-j] = shdr;

			chunk_cm -= CIPHER_META_SZ;
		}

		m += segs;
	}

	n_pkts = m;

	/* allocate mbufs */
	if (n_pkts - n_bufs > 0) {
		ret = rte_mempool_get_bulk(tx_mbuf_pool, (void **)&bufs[n_bufs],
					n_pkts - n_bufs);
		if (unlikely(ret)) {
			stats[TX_COMPLETION_FAIL] += n_pkts - n_bufs;
			log_warn_ratelimited("tx: error getting %d mbufs from mempool", n_pkts - n_bufs);
			return true;
		}
	}

	/* fill in packet metadata */
	for (i = n_bufs; i < n_pkts; i++) {
		if (i + TX_PREFETCH_STRIDE < n_pkts)
			prefetch(seg_hdrs[i + TX_PREFETCH_STRIDE]);
		tx_prepare_tx_mbuf(bufs[i], seg_hdrs[i], seg_ts[i]);
	}

	n_bufs = n_pkts;

	/* finally, send the packets on the wire */
	ret = rte_eth_tx_burst(dp.port, 0, bufs, n_pkts);
	log_debug("tx: transmitted %d packets on port %d", ret, dp.port);

	/* apply back pressure if the NIC TX ring was full */
	if (unlikely(ret < n_pkts)) {
		STAT_INC(TX_BACKPRESSURE, n_pkts - ret);
		n_pkts -= ret;
		for (i = 0; i < n_pkts; i++)
			bufs[i] = bufs[ret + i];
	} else {
		n_pkts = 0;
	}

	n_bufs = n_pkts;
	return true;
}

/*
 * Zero out private data for a packet
 */

static void tx_pktmbuf_priv_init(struct rte_mempool *mp, void *opaque,
				 void *obj, unsigned obj_idx)
{
	struct rte_mbuf *buf = obj;
	struct tx_pktmbuf_priv *data = tx_pktmbuf_get_priv(buf);
	memset(data, 0, sizeof(*data));
}

/*
 * Create and initialize a packet mbuf pool for holding struct mbufs and
 * handling completion events. Actual buffer memory is separate, in shared
 * memory.
 */
static struct rte_mempool *tx_pktmbuf_completion_pool_create(const char *name,
		unsigned n, uint16_t priv_size, int socket_id)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	unsigned elt_size;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		log_err("tx: mbuf priv_size=%u is not aligned", priv_size);
		rte_errno = EINVAL;
		return NULL;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned)priv_size;
	mbp_priv.mbuf_data_room_size = 0;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, 0,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		return NULL;

	ret = rte_mempool_set_ops_byname(mp, "completion", NULL);
	if (ret != 0) {
		log_err("tx: error setting mempool handler");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);
	rte_mempool_obj_iter(mp, tx_pktmbuf_priv_init, NULL);

	return mp;
}

/*
 * Initialize tx state.
 */
int tx_init(void)
{
	/* create a mempool to hold struct rte_mbufs and handle completions */
	tx_mbuf_pool = tx_pktmbuf_completion_pool_create("TX_MBUF_POOL",
			IOKERNEL_NUM_COMPLETIONS, sizeof(struct tx_pktmbuf_priv),
			rte_socket_id());

	if (tx_mbuf_pool == NULL) {
		log_err("tx: couldn't create tx mbuf pool");
		return -1;
	}

	return 0;
}
