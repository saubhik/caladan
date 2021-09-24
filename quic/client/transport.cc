#pragma once

namespace quic {

class QuicClientTransport
    : public QuicTransportBase,
      public AsyncUDPSocket::ReadCallback,
      public AsyncUDPSocket::ErrMessageCallback,
      public std::enable_shared_from_this<QuicClientTransport> {
 public:
  QuicClientTransport(std::unique_ptr<quic::AsyncUDPSocket> socket);
  
  ~QuicClientTransport() override;

  /**
   * Supply the hostname to use to validate the server. Must be set before
   * start().
   */
  void SetHostname(const std::string& hostname);

  /**
   * Supplies a new peer address to use for the connection. This must be called
   * at least once before start().
   */
  void AddNewPeerAddress(quic::SocketAddress peer_address);

  /**
   * Starts the connection.
   */
  virtual void Start(ConnectionCallback* cb);
};

}