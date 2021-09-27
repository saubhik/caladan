#pragma once

extern "C" {
#include <base/kref.h>
#include <runtime/net/defs.h>
#include <runtime/net/waitq.h>
#include <runtime/udp.h>
}

#include <thread>

#include <quic/lib/netops.h>
#include <quic/lib/network_socket.h>
#include <quic/lib/socket_address.h>

namespace quic {

class AsyncUDPSocket {
 public:
  enum class FDOwnership { OWNS, SHARED };

  AsyncUDPSocket(const AsyncUDPSocket&) = delete;
  AsyncUDPSocket& operator=(const AsyncUDPSocket&) = delete;

  class ReadCallback {
   public:
    struct OnDataAvailableParams {
      int gro = -1;
    };

    /**
     * Invoked when the socket becomes readable and we want buffer
     * to write to.
     *
     * NOTE: From socket we will end up reading at most `len` bytes
     *       and if there were more bytes in datagram, we will end up
     *       dropping them.
     */
    virtual void GetReadBuffer(void** buf, size_t* len) noexcept = 0;

    /**
     * Invoked when a new datagram is available on the socket. `len`
     * is the number of bytes read and `truncated` is true if we had
     * to drop few bytes because of running out of buffer space.
     * OnDataAvailableParams::gro is the GRO segment size
     */
    virtual void OnDataAvailable(const quic::SocketAddress& client, size_t len,
                                 bool truncated,
                                 OnDataAvailableParams params) noexcept = 0;

    /**
     * Notifies when data is available. This is only invoked when
     * shouldNotifyOnly() returns true.
     */
    virtual void OnNotifyDataAvailable(AsyncUDPSocket&) noexcept {}

    /**
     * Returns whether or not the read callback should only notify
     * but not call getReadBuffer.
     * If shouldNotifyOnly() returns true, AsyncUDPSocket will invoke
     * onNotifyDataAvailable() instead of getReadBuffer().
     * If shouldNotifyOnly() returns false, AsyncUDPSocket will invoke
     * getReadBuffer() and onDataAvailable().
     */
    virtual bool ShouldNotifyOnly() { return false; }

    /**
     * Invoked when there is an error reading from the socket.
     *
     * NOTE: Since UDP is connectionless, you can still read from the socket.
     *       But you have to re-register readCallback yourself after
     *       onReadError.
     */
    virtual void OnReadError(const AsyncSocketException& ex) noexcept = 0;

    /**
     * Invoked when socket is closed and a read callback is registered.
     */
    virtual void OnReadClosed() noexcept = 0;

    virtual ~ReadCallback() = default;
  };

  class ErrMessageCallback {
   public:
    virtual ~ErrMessageCallback() = default;

    /**
     * errMessage() will be invoked when kernel puts a message to
     * the error queue associated with the socket.
     *
     * @param cmsg      Reference to cmsghdr structure describing
     *                  a message read from error queue associated
     *                  with the socket.
     */
    virtual void ErrMessage(const cmsghdr& cmsg) noexcept = 0;

    /**
     * errMessageError() will be invoked if an error occurs reading a message
     * from the socket error stream.
     *
     * @param ex        An exception describing the error that occurred.
     */
    virtual void ErrMessageError(const AsyncSocketException& ex) noexcept = 0;
  };

  struct WriteOptions {
    WriteOptions() = default;
    WriteOptions(int gsoVal) : gso(gsoVal) {}
    int gso{0};
  };

  /**
   * Returns the address server is listening on
   */
  virtual const quic::SocketAddress& Address() const {
    // CHECK_NE(NetworkSocket(), fd_) << "Server not yet bound to an address";
    return local_address_;
  }

  /**
   * Bind the socket to the following address. If port is not
   * set in the `address` an ephemeral port is chosen and you can
   * use `Address()` method above to get it after this method successfully
   * returns.
   */
  virtual void Bind(const quic::SocketAddress& address);

  /**
   * Connects the UDP socket to a remote destination address provided in
   * address. This can speed up UDP writes on linux because it will cache flow
   * state on connects.
   * Using connect has many quirks, and you should be aware of them before using
   * this API:
   * 1. If this is called before bind, the socket will be automatically bound to
   * the IP address of the current default network interface.
   * 2. Normally UDP can use the 2 tuple (src ip, src port) to steer packets
   * sent by the peer to the socket, however after connecting the socket, only
   * packets destined to the destination address specified in connect() will be
   * forwarded and others will be dropped. If the server can send a packet
   * from a different destination port / IP then you probably do not want to use
   * this API.
   * 3. It can be called repeatedly on either the client or server however it's
   * normally only useful on the client and not server.
   */
  virtual void Connect(const quic::SocketAddress& address);

 private:
  void Init(sa_family_t family);

  NetworkSocket fd_;
  FDOwnership ownership_;

  // Temp space to receive client address.
  quic::SocketAddress client_address_;

  quic::SocketAddress local_address_;

  // If the socket is connected.
  quic::SocketAddress connected_address_;
  bool connected_{false};
};

}  // namespace quic
