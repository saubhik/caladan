#pragma once

extern "C" {
#include <base/log.h>
}

#include <iostream>
#include <map>
#include <string>
#include <thread>

namespace quic {

class Client : public quic::QuicSocket::ConnectionCallback,
               public quic::QuicSocket::ReadCallback,
               public quic::QuicSocket::WriteCallback {
 public:
  Client(const std::string& host, uint16_t port) : host_(host), port_(port) {}

  void ReadAvailable(quic::StreamId id) noexcept override {
    auto read_data = quic_client_->Read(id, 0);
  }

  void ReadError(quic::StreamId id,
                 quic::QuicErrorCode error) noexcept override {
    log_err("Client failed read from stream");
  }

  void OnNewBidirectionalStream(quic::StreamId id) noexcept override {
    log_info("Client: new bidirectional stream");
    quic_client_->SetReadCallback(id, this);
  }

  void OnNewUnidirectionalStream(quic::StreamId id) noexcept override {
    log_info("Client: new unidirectional stream");
    quic_client_->SetReadCallback(id, this);
  }

  void OnStopSending(quic::StreamId id,
                     quic::ApplicationErrorCode error) noexcept override {
    log_err("Client got StopSending");
  }

  void OnConnectionEnd() noexcept override {
    log_info("Client: connection end");
  }

  void OnConnectionError(quic::QuicErrorCode error) noexcept override {
    log_err("Client connection error");
  }

  void OnTransportReady() noexcept override {}

  void OnStreamWriteReady(quic::StreamId id,
                          uint64_t max_to_send) noexcept override {
    log_info("Client is write ready with max_to_send=%ld", max_to_send);
    SendMessage(id, pending_output_[id]);
  }

  void OnStreamWriteError(quic::StreamId id,
                          quic::QuicErrorCode error) noexcept override {
    log_err("Client write error with stream");
  }

  void Start() {
    auto sock = std::make_unique<quic::AsyncUDPSocket>();
    quic::SocketAddress addr(host_.c_str(), port_);

    quic_client_ = std::make_shared<quic::QuicClientTransport>(std::move(sock));
    quic_client_->SetHostName("echo.com");
    quic_client_->AddNewPeerAddress(addr);

    quic::TransportSettings settings;
    quic_client_->SetTransportSettings(settings);
    quic_client_->SetTransportStatsCallback(
        std::make_shared<LogQuicStats>("client"));
    log_info("Client connecting to: %s", addr.describe());
    quic_client_->Start(this);
  }

  ~Client() override = default;

 private:
  void SendMessage(quic::StreamId id, BufQueue& data) {
    auto message = data.move();
    auto res = quic_client_->WriteChain(id, message->clone, true);
  }

  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quic_client_;
  std::map<quic::StreamId, BufQueue> pending_output_;
  std::map<quic::StreamId, uint64_t> recv_offsets_;
};

}  // namespace quic
