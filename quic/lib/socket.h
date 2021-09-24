#pragma once

extern "C" {
#include <runtime/udp.h>
}

#include <thread>

#include <lib/socket_address.h>

namespace quic {

class AsyncUDPSocket {
 public:
  AsyncUDPSocket(const AsyncUDPSocket&) = delete;
  AsyncUDPSocket& operator=(const AsyncUDPSocket&) = delete;

  virtual void connect(const quic::SocketAddress& address);

  /**
   * Send the data in buffer to destination. Returns the return code from
   * ::sendmsg.
   */
  virtual ssize_t write(
      const quic::SocketAddress& address,
      const std::unique_ptr<quic::IOBuf>& buf);

  /**
   * Stop listening on the socket.
   */
  virtual void close();

 private:
  udpconn_t *sock_;
  quic::SocketAddress local_address_;
  quic::SocketAddress connected_address_;
  bool connected_{false};
};

} // namespace quic
