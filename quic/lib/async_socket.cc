extern "C" {
#include <runtime/smalloc.h>
#include <runtime/udp.h>
}

#include <quic/lib/async_socket.h>
#include <quic/lib/async_socket_exception.h>

#include <cstddef>

namespace quic {

void AsyncUDPSocket::Init(sa_family_t family) {
  NetworkSocket socket =
      netops::socket(family, SOCK_DGRAM, family != AF_UNIX ? SH_IPPROTO_UDP : 0);
  if (socket == NetworkSocket()) {
    throw AsyncSocketException(AsyncSocketException::NOT_OPEN,
                               "error creating async udp socket", errno);
  }

  fd_ = socket;
  ownership_ = FDOwnership::OWNS;
}

void AsyncUDPSocket::Bind(const quic::SocketAddress& address) {
  Init(address.GetFamily());

  sockaddr_storage addr_storage;
  address.GetAddress(&addr_storage);
  auto& saddr = reinterpret_cast<sockaddr&>(addr_storage);
  if (netops::bind(fd_, &saddr, address.GetActualSize()) != 0) {
    throw AsyncSocketException(
        AsyncSocketException::NOT_OPEN,
        "failed to bind the async udp socket for: " + address.Describe(),
        errno);
  }

  if (address.GetFamily() == AF_UNIX || address.GetPort() != 0) {
    local_address_ = address;
  } else {
    local_address_.SetFromLocalAddress(fd_);
  }
}

}  // namespace quic
