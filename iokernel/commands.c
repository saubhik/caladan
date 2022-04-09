/*
 * commands.c - dataplane commands to/from runtimes
 */

#include <rte_mbuf.h>

#include <base/log.h>
#include <base/lrpc.h>
#include <iokernel/queue.h>

#include "defs.h"

typedef struct pair {
	int n_bufs, n_hdrs;
} pair;

static void commands_drain_queue(
	pair *p, struct thread *t, struct rte_mbuf **bufs, int n, struct buf_hdr **hdrs)
{
	int i;

	for (i = 0; i < n; i++) {
		uint64_t cmd;
		unsigned long payload;

		if (!lrpc_recv(&t->txcmdq, &cmd, &payload))
			break;

		switch (cmd) {
		case TXCMD_NET_COMPLETE:
			bufs[p->n_bufs++] = (struct rte_mbuf *)payload;
			/* TODO: validate pointer @buf */
			break;

		case TXCMD_NET_BUF:
			hdrs[p->n_hdrs++] = shmptr_to_ptr(
				&t->p->region, payload, sizeof(struct buf_hdr));
			break;

		default:
			/* kill the runtime? */
			BUG();
		}
	}
}

/*
 * Process a batch of commands from runtimes.
 */
bool commands_rx(void)
{
	struct buf_hdr *hdrs[IOKERNEL_CMD_BURST_SIZE];
	struct rte_mbuf *bufs[IOKERNEL_CMD_BURST_SIZE];
	int i;
	static unsigned int pos = 0;
	pair p = {0, 0};

	/*
	 * Poll each thread in each runtime until all have been polled or we
	 * have processed CMD_BURST_SIZE commands.
	 */
	for (i = 0; i < nrts; i++) {
		unsigned int idx = (pos + i) % nrts;

		if (p.n_bufs + p.n_hdrs >= IOKERNEL_CMD_BURST_SIZE)
			break;

		commands_drain_queue(
			&p, ts[idx], (struct rte_mbuf **) &bufs,
				IOKERNEL_CMD_BURST_SIZE - (p.n_bufs + p.n_hdrs),
				(struct buf_hdr **) &hdrs);
	}

	STAT_INC(COMMANDS_PULLED, n_bufs);

	pos++;
	for (i = 0; i < p.n_bufs; i++)
		rte_pktmbuf_free(bufs[i]);

	// Process the hdrs[i].

	return (p.n_bufs + p.n_hdrs) > 0;
}
