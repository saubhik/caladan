#pragma once

namespace quic {

class QuicTransportBase : public QuicSocket {
 public:
   QuicTransportBase(std::unique_ptr<quic::AsyncUDPSocket> socket);

   ~QuicTransportBase() override;
};

}