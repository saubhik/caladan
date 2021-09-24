namespace quic {

void AsyncUDPSocket::connect(const SocketAddress& address) {
  sockaddr_storage addr_storage;
  address.GetAddress(&addr_storage);

  // TODO: How to get laddr, raddr from address?
  // TODO: Make udpconn_t *c a private var?

  int ret = udp_dial(laddr, raddr, &sock);
  if (ret) {
    throw AsyncSocketException(
      AsyncSocketException::NOT_OPEN,
      "Failed to connect the udp socket to:" + address.describe(),
      errno);
    )
  }

  connected_ = true;
  connected_address_ = address;
}

}