/*
 *  sh_event.h - support for libevent-like eventing
 */

#pragma once

extern "C" {
#include <runtime/poll.h>
}

#include "net.h"

namespace rt {

class EventLoop;

class Event {
public:
  static Event *CreateEvent(UdpConn *sock, short event_type,
                            sh_event_callback_fn cb, void *arg) {
    poll_trigger_t *t;
    int ret = create_trigger(&t);
    if (ret) {
      return nullptr;
    }

    auto *event = new Event(t);
    event->event_type_ = event_type;
    event->cb_ = cb;
    event->cb_arg_ = arg;
    event->sock_ = sock;

    return event;
  }

  static void AddEvent(Event* event, const struct timeval *tv);
  static void DelEvent(Event* event) { poll_disarm(event->t_); }

  rt::UdpConn* GetSocket() { return this->sock_; }
  void SetEventLoop(EventLoop *evl) { evl_ = evl; }
  bool IsEventRegistered() { return t_->waiter != nullptr; };

private:
  explicit Event(poll_trigger_t *t) : t_(t), evl_(nullptr) {}

  // disable move and copy.
  Event(const Event &) = delete;
  Event &operator=(const Event &) = delete;

  poll_trigger_t *t_;
  rt::EventLoop *evl_;
  short event_type_;
  sh_event_callback_fn cb_;
  void *cb_arg_;
  rt::UdpConn *sock_;
};

class EventLoop {
public:
  static EventLoop *CreateWaiter() {
    poll_waiter_t *w;
    int ret = create_waiter(&w);
    if (ret)
      return nullptr;
    return new EventLoop(w);
  }

  poll_waiter_t *GetWaiter() { return w_; }

  int LoopCbOnce() { return poll_cb_once(w_); }

	int LoopCbOnceNonblock() { return poll_cb_once_nonblock(w_); }

private:
  EventLoop(poll_waiter_t *w) : w_(w) {}

  // disable move and copy.
  EventLoop(const EventLoop &) = delete;
  EventLoop &operator=(const EventLoop &) = delete;

  poll_waiter_t *w_;
};
} // namespace rt
