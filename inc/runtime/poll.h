/*
 * poll.h - support for event polling (similar to select/epoll/poll, etc.)
 */

#pragma once

#include <base/stddef.h>
#include <base/list.h>
#include <runtime/thread.h>
#include <runtime/sync.h>
#include <runtime/udp.h>

// Bitmap for different event types (based on libevent)
#define SEV_TIMEOUT      0x01
#define SEV_READ         0x02
#define SEV_WRITE        0x04
#define SEV_SIGNAL       0x08
#define SEV_PERSIST      0x10
#define SEV_ET           0x20

// Maximum number of callbacks to trigger in a single call
#define MAX_AT_ONCE	100

typedef void(* sh_event_callback_fn) (void * args);

typedef struct poll_waiter {
	spinlock_t		lock;
	struct list_head	triggered;
	thread_t		*waiting_th;
	uint16_t		counter;
} poll_waiter_t;

typedef struct poll_trigger {
	struct list_node	link;
	struct list_node	sock_link;
	struct poll_waiter	*waiter;
	bool			triggered;
	short			event_type;
	sh_event_callback_fn	cb;
	void*			cb_arg;
	unsigned long		data;
	udpconn_t *sock;
} poll_trigger_t;


/*
 * Waiter API
 */

extern int create_waiter(poll_waiter_t **w_out);
extern void poll_init(poll_waiter_t *w);
extern void poll_arm(poll_waiter_t *w, poll_trigger_t *t, unsigned long data);
extern void poll_arm_w_sock(poll_waiter_t *w, struct list_head *sock_event_head,
        poll_trigger_t *t, short event_type, sh_event_callback_fn cb,
        void* cb_arg, udpconn_t *sock);
extern void poll_disarm(poll_trigger_t *t);
extern unsigned long poll_wait(poll_waiter_t *w);
extern int poll_cb_once(poll_waiter_t *w);
extern int poll_cb_once_nonblock(poll_waiter_t *w);

/*
 * Trigger API
 */
extern int create_trigger(poll_trigger_t **t_out);

/**
 * poll_trigger_init - initializes a trigger
 * @t: the trigger to initialize
 */
static inline void poll_trigger_init(poll_trigger_t *t)
{
	t->waiter = NULL;
	t->triggered = false;
}

extern void poll_trigger(poll_waiter_t *w, poll_trigger_t *t);
