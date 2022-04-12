/*
 * commands.c - dataplane commands to/from runtimes
 */

#include <rte_mbuf.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <iokernel/queue.h>

#include <stdio.h>

#include "defs.h"
#include "../fizzwrapper/codeccapi.h"

typedef struct pair {
	int n_bufs, n_hdrs;
} pair;

static void commands_drain_queue(
	pair *pr,
	struct thread *t,
	struct rte_mbuf **bufs,
	int n,
	struct buf_hdr **hdrs,
	struct thread **threads
)
{
	int i;

	for (i = 0; i < n; i++) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&t->txcmdq, &cmd, &payload))
			break;

		switch (cmd) {
		case TXCMD_NET_COMPLETE:
			bufs[pr->n_bufs++] = (struct rte_mbuf *)payload;
			/* TODO: validate pointer @buf */
			break;

		case TXCMD_NET_BUF:
			hdrs[pr->n_hdrs] = shmptr_to_ptr(
				&t->p->region, payload, sizeof(struct buf_hdr));
			threads[pr->n_hdrs] = t;
			++pr->n_hdrs;
			break;

		default:
			/* kill the runtime? */
			BUG();
		}
	}
}

/*
 * Send a completion event to the runtime for the buf in hdr.
 */
static bool buf_send_completion(struct thread *th, struct buf_hdr *hdr)
{
	struct proc *p;

	p = th->p;

	/* during initialization, the bufs are enqueued for the first time */
	if (unlikely(!p))
		return true;

	/* check if runtime is still registered */
	if (unlikely(p->kill)) {
		proc_put(p);
		return true;
	}

	/* send completion to runtime */
	if (th->active) {
		if (likely(lrpc_send(
			&th->rxq, RX_NET_BUF_COMPLETE, hdr->completion_data))) {
			goto success;
		}
	} else {
		if (likely(rx_send_to_runtime(
			p, p->next_thread_rr++, RX_NET_BUF_COMPLETE,
			hdr->completion_data))) {
			goto success;
		}
	}

	if (unlikely(p->buf_nr_overflows == p->buf_max_overflows)) {
		log_warn("buf: Completion overflow queue is full");
		return false;
	}
	p->buf_overflow_queue[p->buf_nr_overflows++] = hdr->completion_data;
	log_debug_ratelimited("buf: failed to send completion to runtime");

success:
	proc_put(p);
	return true;
}

static int drain_overflow_queue(struct proc *p, int n)
{
	int i = 0;
	while (p->buf_nr_overflows > 0 && i < n) {
		if (!rx_send_to_runtime(p, p->next_thread_rr++, RX_NET_BUF_COMPLETE,
				p->buf_overflow_queue[--p->buf_nr_overflows])) {
			p->buf_nr_overflows++;
			break;
		}
		i++;
	}
	return i;
}

bool buf_drain_completions(void)
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

/*
 * Process a batch of commands from runtimes.
 */
bool commands_rx(void)
{
	struct buf_hdr *hdrs[IOKERNEL_CMD_BURST_SIZE];
	struct rte_mbuf *bufs[IOKERNEL_CMD_BURST_SIZE];
	struct thread *threads[IOKERNEL_CMD_BURST_SIZE];
	int i;
	static unsigned int pos = 0;
	pair pr = {0, 0};
	struct thread *t;
	struct buf_hdr *hdr;

	/*
	 * Poll each thread in each runtime until all have been polled or we
	 * have processed CMD_BURST_SIZE commands.
	 */
	for (i = 0; i < nrts; i++) {
		unsigned int idx = (pos + i) % nrts;
		t = ts[idx];

		if (pr.n_bufs + pr.n_hdrs >= IOKERNEL_CMD_BURST_SIZE)
			break;

		commands_drain_queue(&pr, t, (struct rte_mbuf **) &bufs,
			IOKERNEL_CMD_BURST_SIZE - (pr.n_bufs + pr.n_hdrs),
			(struct buf_hdr **) &hdrs, (struct thread **) &threads);
	}

	STAT_INC(COMMANDS_PULLED, n_bufs);

	pos++;
	for (i = 0; i < pr.n_bufs; i++)
		rte_pktmbuf_free(bufs[i]);

	// Process the hdrs[i].
	for (i = 0; i < pr.n_hdrs; ++i) {
		t = threads[i];
		hdr = hdrs[i];

		/* reference count @p so it doesn't get freed before the completion */
		proc_get(t->p);

#if 0
		int j;
		printf("%s\n", "buf: received hdr->payload:");
		for (j = 0; j < hdr->len; ++j) {
			printf("%2x, ", (uint8_t)hdr->payload[j]);
		}
		printf("\n");
#endif

		uint8_t cipherKind = hdr->payload[0];
		uint8_t* secret = (uint8_t*)hdr->payload + 1;
		ssize_t secretLen = hdr->len - 1;
		CiphersC *ciphers = CiphersC_create(cipherKind, secret, secretLen);
		(void)ciphers;

		// Give up on notifying the runtime if this returns false.
		buf_send_completion(t, hdr);
	}

	return (pr.n_bufs + pr.n_hdrs) > 0;
}
