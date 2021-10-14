#include <quic/lib/netops.h>

#include <runtime/smalloc.h>

#define UDP_IN_DEFAULT_CAP 512
#define UDP_OUT_DEFAULT_CAP 2048

namespace quic {

NetworkSocket socket(int af, int type, int protocol) {
  sh_assert(type == SOCK_DGRAM);

  quic::NativeSocket sock;
  sock = static_cast<quic::NativeSocket>(smalloc(sizeof sock));
  if (!sock) return NetworkSocket();

  sock->shutdown = false;

  // initialize ingress fields
  spin_lock_init(&sock->inq_lock);
  sock->inq_cap = UDP_IN_DEFAULT_CAP;
  sock->inq_len = 0;
  sock->inq_err = 0;
  waitq_init(&sock->inq_wq);
  mbufq_init(&sock->inq);

  // initialize egress fields
  spin_lock_init(&sock->outq_lock);
  sock->outq_free = false;
  sock->outq_cap = UDP_OUT_DEFAULT_CAP;
  sock->outq_len = 0;
  waitq_init(&sock->outq_wq);

  kref_init(&sock->ref);

  return NetworkSocket(sock);
}

}  // namespace quic
