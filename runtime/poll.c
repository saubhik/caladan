/*
 * poll.h - support for event polling (similar to select/epoll/poll, etc.)
 */

#include <runtime/poll.h>
#include <runtime/smalloc.h>
#include "net/mbufq.h"

/**
 * poll_init - initializes a polling waiter object
 * @w: the waiter object to initialize
 */
void poll_init(poll_waiter_t *w)
{
	spin_lock_init(&w->lock);
	list_head_init(&w->triggered);
	w->waiting_th = NULL;
	w->counter = 0;
}

/**
 * create_waiter - allocate memory for waiter and initialize it
 * @w_out: a pointer to store the waiter (if successful)
 */
int create_waiter(poll_waiter_t **w_out)
{
	poll_waiter_t *w;
	w = smalloc(sizeof(*w));
	if (!w)
		return -ENOMEM;
	poll_init(w);
	*w_out = w;
	return 0;
}

/**
 * create_trigger - allocate memory for trigger
 * @t_out: a pointer to store the trigger (if successful)
 */
int create_trigger(poll_trigger_t **t_out)
{
	poll_trigger_t *t;
	t = smalloc(sizeof(*t));
	if (!t)
		return -ENOMEM;

	poll_trigger_init(t);
	*t_out = t;
	return 0;
}

/**
 * poll_arm - registers a trigger with a waiter
 * @w: the waiter to register with
 * @t: the trigger to register
 * @data: data to provide when the trigger fires
 */
void poll_arm(poll_waiter_t *w, poll_trigger_t *t, unsigned long data)
{
	if (WARN_ON(t->waiter != NULL))
		return;

	t->waiter = w;
	t->triggered = false;
	t->data = data;

	spin_lock_np(&w->lock);
	w->counter++;
	spin_unlock_np(&w->lock);
}

/**
 * poll_arm_w_sock -  register a trigger with a waiter and a socket
 * @w: the waiter to register with
 * @sock_event_head: the list head of triggers associated with the socket
 * @t: the trigger to register
 * @cb: the callback called with the trigger fires
 * @cb_arg: the argument passed to the callback
 */
void poll_arm_w_sock(poll_waiter_t *w, struct list_head *sock_event_head,
	poll_trigger_t *t, short event_type, sh_event_callback_fn cb,
	void* cb_arg, udpconn_t *sock) {
	if (WARN_ON(t->waiter != NULL))
		return;

	t->waiter = w;
	t->triggered = false;
	t->event_type = event_type;
	t->cb = cb;
	t->cb_arg = cb_arg;
	t->sock = sock;
	list_add(sock_event_head, &t->sock_link);

	spin_lock_np(&w->lock);
	w->counter++;
	spin_unlock_np(&w->lock);
}

/**
 * poll_disarm - unregisters a trigger with a waiter
 * @t: the trigger to unregister
 */
void poll_disarm(poll_trigger_t *t)
{
	poll_waiter_t *w;
	if (WARN_ON(t->waiter == NULL))
		return;

	w = t->waiter;
	spin_lock_np(&w->lock);
	if (t->triggered) {
		list_del(&t->link);
		t->triggered = false;
	}
	w->counter--;
	spin_unlock_np(&w->lock);

	t->waiter = NULL;
}

/**
 * poll_wait - waits for the next event to trigger
 * @w: the waiter to wait on
 *
 * Returns the data provided to the trigger that fired
 */
unsigned long poll_wait(poll_waiter_t *w)
{
	thread_t *th = thread_self();
	poll_trigger_t *t;

	while (true) {
		spin_lock_np(&w->lock);
		t = list_pop(&w->triggered, poll_trigger_t, link);
		if (t) {
			spin_unlock_np(&w->lock);
			return t->data;
		}
		w->waiting_th = th;
		thread_park_and_unlock_np(&w->lock);
	}
}

/**
 * poll_cb_once - loops over all triggered events and calls their callbacks
 * @w: the waiter to wait on
 */
int poll_cb_once_nonblock(poll_waiter_t *w)
{
	poll_trigger_t *t;
	int ret = 1;

	/* (@saubhik): If no event is triggered, return.
	 * If a triggered event is found, then process it,
	 * and process all triggered events, and return.
	 */
	while (true) {
		spin_lock_np(&w->lock);

		if (!w->counter) {
			spin_unlock_np(&w->lock);
			return -1;
		}

		t = list_pop(&w->triggered, poll_trigger_t, link);

		if (!t) {
			spin_unlock_np(&w->lock);
			return ret;
		}

		t->triggered = false;
		spin_unlock_np(&w->lock);
		t->cb(t->cb_arg);

		udp_conn_check_triggers(t->sock);
		ret = 0;
	}
}

/**
 * poll_cb_once - blocks till an event is triggered and loops over all
 * triggered events and calls their callbacks
 * @w: the waiter to wait on
 */
int poll_cb_once(poll_waiter_t *w)
{
	bool processed_events = false;
	poll_trigger_t *t;

	while (true) {
		spin_lock_np(&w->lock);
		if (!w->counter) {
			spin_unlock_np(&w->lock);
			return 1;
		}

		t = list_pop(&w->triggered, poll_trigger_t, link);

		if (!t) {
			spin_unlock_np(&w->lock);
			if (processed_events) return 0;
			return 1;
		}

		t->triggered = false;
		spin_unlock_np(&w->lock);
		t->cb(t->cb_arg);
		processed_events = true;

		udp_conn_check_triggers(t->sock);
	}
}

/**
 * poll_trigger - fires a trigger
 * @w: the waiter to wake up (if it is waiting)
 * @t: the trigger that fired
 */
void poll_trigger(poll_waiter_t *w, poll_trigger_t *t)
{
	thread_t *wth = NULL;

	spin_lock_np(&w->lock);
	if (t->triggered) {
		spin_unlock_np(&w->lock);
		return;
	}
	t->triggered = true;
	list_add(&w->triggered, &t->link);
	if (w->waiting_th) {
		wth = w->waiting_th;
		w->waiting_th = NULL;
	}
	spin_unlock_np(&w->lock);

	if (wth)
		thread_ready(wth);
}
