#include "sh_event.h"

namespace rt {
void Event::AddEvent(Event *event, const struct timeval *tv) {
  // TODO: Do we need to add event timeouts?
  poll_arm_w_sock(event->evl_->GetWaiter(), event->sock_->EventList(),
                  event->t_, SEV_READ, event->cb_, event->cb_arg_);
}
} // namespace rt