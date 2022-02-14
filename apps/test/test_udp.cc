extern "C" {
#include <base/log.h>
}

#include "runtime.h"
#include "net.h"
#include "timer.h"

#include <memory>
#include <iostream>
#include <vector>


namespace {

struct netaddr raddr;
const unsigned int MAX_BUF_LENGTH = 131072;
constexpr uint8_t seconds = 60;
constexpr uint64_t serverPort = 8001;

void ServerHandler(void *arg) {
	std::vector<char> buf(MAX_BUF_LENGTH);
	std::unique_ptr<rt::UdpConn> udpConn(
		rt::UdpConn::Listen({0, serverPort}));
	if (udpConn == nullptr) panic("couldn't listen for connections");
	ulong bytesReceived = 0;
	ssize_t ret;
	while (true) {
		ret = udpConn->ReadFrom(&buf[0], buf.size(), &raddr);
		std::string rcv(buf.begin(), buf.begin() + ret);
		if (rcv == "DONE") break;
		bytesReceived += ret;
	}
	udpConn->Shutdown();
	log_info("server received @ %f Gb/s", ((double)bytesReceived / 134217728) / seconds);
}

void ClientHandler(void *arg) {
	ssize_t ret;
	ulong bytesSent = 0;
	std::unique_ptr<rt::UdpConn> udpConn(
		rt::UdpConn::Dial({0, 0}, raddr));
	if (unlikely(udpConn == nullptr)) panic("couldn't connect to raddr.");
	log_info("Starting sends to server...");
	std::string snd(1458 * 5, 'a'); // 1458 * 5 = 7290.
	uint64_t stop_us = rt::MicroTime() + seconds * rt::kSeconds;
	while (rt::MicroTime() < stop_us) {
		ret = udpConn->Write(&snd[0], snd.size());
		if (ret != static_cast<ssize_t>(snd.size())) {
			panic("write failed, ret = %ld", ret);
		}
		bytesSent += ret;
	}
	log_info("client sent @ %f Gb/s", ((double)bytesSent / 134217728) / seconds);
	while (true) {
		snd = std::string("DONE");
		ret = udpConn->Write(&snd[0], snd.size());
		if (ret != static_cast<ssize_t>(snd.size())) {
			panic("write failed, ret = %ld", ret);
		}
	}
	udpConn->Shutdown();
}

} // namespace

int main(int argc, char *argv[]) {
	int ret;
	if (argc < 3) {
		std::cerr << "usage: [cfg_file] [cmd] ..." << std::endl;
		return -EINVAL;
	}
	std::string cmd = argv[2];
	if (cmd == "server") {
		ret = runtime_init(argv[1], ServerHandler, nullptr);
		if (ret) {
			printf("failed to start runtime\n");
			return ret;
		}
	} else if (cmd != "client") {
		std::cerr << "usage: [cfg_file] client [remote_ip]" << std::endl;
		return -EINVAL;
	}
	raddr = rt::StringToNetaddr(argv[3]);
	raddr.port = serverPort;
	ret = runtime_init(argv[1], ClientHandler, nullptr);
	if (ret) {
		printf("failed to start runtime\n");
		return ret;
	}
	return 0;
}
