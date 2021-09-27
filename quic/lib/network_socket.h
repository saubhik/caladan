#pragma once

extern "C" {
#include <base/kref.h>
#include <base/types.h>
#include <net/mbufq.h>
#include <runtime/net/defs.h>
#include <runtime/net/waitq.h>
}

#include <functional>

namespace quic {

struct UDPSocket {
  struct trans_entry e;
  bool shutdown;

  /* ingress support */
  spinlock_t inq_lock;
  int inq_cap;
  int inq_len;
  int inq_err;
  waitq_t inq_wq;
  struct mbufq inq;

  /* egress support */
  spinlock_t outq_lock;
  bool outq_free;
  int outq_cap;
  int outq_len;
  waitq_t outq_wq;

  struct kref ref;
  struct flow_registration flow;
};

using NativeSocket = UDPSocket *;

struct NetworkSocket {
  NativeSocket data;

  constexpr NetworkSocket() : data(nullptr) {}
  constexpr explicit NetworkSocket(NativeSocket d) : data(d) {}

  template <typename T>
  static NetworkSocket FromFd(T) = delete;
  static NetworkSocket FromFd(int fd) {
    return NetworkSocket(SocketFileDescriptorMap::FdToSocket(fd));
  }

  int toFd() const { return SocketFileDescriptorMap::SocketToFd(data); }

  friend constexpr bool operator==(const NetworkSocket &a,
                                   const NetworkSocket &b) noexcept {
    return a.data == b.data;
  }

  friend constexpr bool operator!=(const NetworkSocket &a,
                                   const NetworkSocket &b) noexcept {
    return !(a == b);
  }
};

struct SocketFileDescriptorMap {
  static int Close(int fd) noexcept;
  static NativeSocket FdToSocket(int fd) noexcept;
  static int SocketToFd(NativeSocket socket) noexcept;
};

}  // namespace quic

namespace std {

template <>
struct hash<quic::NetworkSocket> {
  size_t operator()(const quic::NetworkSocket &s) const noexcept {
    return std::hash<quic::NativeSocket>()(s.data);
  }
};

}  // namespace std
