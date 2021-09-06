extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "runtime.h"
#include "net.h"

#include <iostream>
#include <string>
#include <memory>

netaddr raddr;
constexpr uint64_t simplePort = 8001;

void ServerHandler(void *arg) {
    std::unique_ptr<rt::TcpQueue> q(rt::TcpQueue::Listen({0, simplePort}, 4096));
    if (q == nullptr) panic("couldn't listen for connections");

    while (true) {
        rt::TcpConn *c = q->Accept();
        if (c == nullptr) panic("couldn't accept a connection");
    }
}

void ClientHandler(void *arg) {
    std::unique_ptr<rt::TcpConn> conn(rt::TcpConn::Dial({0, 0}, raddr));
    if (unlikely(conn == nullptr)) panic("couldn't connect to raddr");
}

int StringToAddr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;

  if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) return -EINVAL;

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

int main(int argc, char *argv[]) {
    int ret;

    if (argc < 3) {
        std::cerr << "usage: [cfg_file] [cmd] ..." << std::endl;
        return -EINVAL;
    }

    std::string cmd = argv[2];
    if (cmd.compare("server") == 0) {
        ret = runtime_init(argv[1], ServerHandler, NULL);
        if (ret) {
            printf("failed to start runtime\n");
            return ret;
        }
    } else if (cmd.compare("client") != 0) {
        std::cerr << "usage: [cfg_file] client [remote_ip]" << std::endl;
        return -EINVAL;
    }

    ret = StringToAddr(argv[3], &raddr.ip);
    if (ret) return -EINVAL;
    raddr.port = simplePort;

    ret = runtime_init(argv[1], ClientHandler, NULL);
    if (ret) {
        printf("failed to start runtime\n");
        return ret;
    }

    return 0;
}
