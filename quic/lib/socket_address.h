#pragma once

namespace quic {

class SocketAddress {
 public:
  SocketAddress() = default;

  /**
   * Initialize this SocketAddress from a socket's local address.
   *
   * Raises std::system_error on error.
   */
  void SetFromLocalAddress(NetworkSocket socket);

  /**
   * Fill in a given sockaddr_storage with the ip or unix address.
   *
   * Returns the actual size of the storage used.
   */
  socklen_t GetAddress(sockaddr_storage* addr) const {
    if (!external_) {
      return storage_.addr.toSockaddrStorage(addr, htons(port_));
    } else {
      memcpy(addr, storage_.un.addr, sizeof(*storage_.un.addr));
      return storage_.un.len;
    }
  }

  socklen_t GetActualSize() const;

  sa_family_t GetFamily() const { return storage_.addr.family(); }

  /**
   * Get the IPv4 or IPv6 port for this address.
   *
   * Raises std::invalid_argument if this is not an IPv4 or IPv6 address.
   *
   * @return Returns the port, in host byte order.
   */
  uint16_t GetPort() const;

  /**
   * Get human-readable string representation of the address.
   *
   * This prints a string representation of the address, for human consumption.
   * For IP addresses, the string is of the form "<IP>:<port>".
   */
  std::string Describe() const;

 private:
  /*
   * storage_ contains room for a full IPv4 or IPv6 address, so they can be
   * stored inline without a separate allocation on the heap.
   *
   * If we need to store a Unix socket address, ExternalUnixAddr is a shim to
   * track a struct sockaddr_un allocated separately on the heap.
   */
  union AddrStorage {
    IPAddress addr;
    ExternalUnixAddr un;
    AddrStorage() : addr() {}
  } storage_{};

  // IPAddress class does not save port, and must be saved here
  uint16_t port_{0};

  bool external_{false};
};

}  // namespace quic
