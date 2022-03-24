extern "C" {
#include <base/log.h>
#include <net/ip.h>
}

#include "net.h"
#include "runtime.h"
#include "thread.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

netaddr raddr;
constexpr uint64_t simplePort = 8001;

//std::string ReadMessage(std::unique_ptr<rt::UdpConn> &conn) {
//  uint32_t len;
//  ssize_t ret = conn->Read(&len, sizeof(uint32_t));
//  if (ret != static_cast<ssize_t>(sizeof(uint32_t))) {
//    panic("read failed, ret = %ld", ret);
//  }
//
//  std::vector<uint8_t> buf;
//  buf.resize(len, 0x00);
//  ret = conn->ReadFull(&buf[0], len);
//  if (ret != static_cast<ssize_t>(len)) {
//    panic("read failed, ret = %ld", ret);
//  }
//
//  std::string msg;
//  msg.assign(buf.begin(), buf.end());
//
//  return msg;
//}

//void WriteMessage(std::unique_ptr<rt::UdpConn> &conn, const std::string &msg) {
//  uint32_t len = msg.size();
//  ssize_t ret = conn->Write(&len, sizeof(uint32_t));
//  if (ret != static_cast<ssize_t>(sizeof(uint32_t))) {
//    panic("write failed, ret = %ld", ret);
//  }
//
//  ret = conn->Write(msg.c_str(), len);
//  if (ret != static_cast<ssize_t>(len)) {
//    panic("write failed, ret = %ld", ret);
//  }
//}

//void ServerWorker(std::unique_ptr<rt::UdpConn> conn) {
//  std::string msg = ReadMessage(conn);
//  log_info("a client sent %s", msg.c_str());
//  WriteMessage(conn, msg);
//}

void ServerHandler(void *arg) {
  netaddr raddr;
  ssize_t ret;
  uint32_t value[21], retval[21];
  std::unique_ptr<rt::UdpConn> conn(rt::UdpConn::Listen({0, simplePort}));
  if (conn == nullptr) panic("couldn't listen for connections");

  while (true) {
    ret = conn->ReadFrom(&value, sizeof(value), &raddr);
    for (int i = 1; i < 17; i++) {
      std::cout << value[i] << " ";
    }
    std::cout << std::endl;
    if (ret != sizeof(value)) {
	    panic("wrong message size");
    }
    for (int i = 1; i < 17; i++) {
      retval[i] = value[i];
    }
    retval[0] = 0xFF;
    conn->WriteTo(&retval, sizeof(retval), &raddr);
    //rt::Thread([=] { ServerWorker(std::unique_ptr<rt::TcpConn>(conn)); })
    //    .Detach();
  }
}

void ClientHandler(void *arg) {
  std::unique_ptr<rt::UdpConn> conn(rt::UdpConn::Dial({0, 0}, raddr));
  if (unlikely(conn == nullptr)) panic("couldn't connect to raddr");

  uint32_t msg[21], res[21] = {0, };
  log_info("please type uint below:");
  std::cin >> msg[0];
  for (int i = 1; i < 17; i++) {
    msg[i] = msg[0];
  }
  msg[0] = 0xFF;
  ssize_t ret = conn->Write(&msg, sizeof(msg));
  if (ret != sizeof(msg)) panic("unable to send message");
  ssize_t mret = conn->Read(&res, sizeof(res));
  for (int i = 1; i < 17; i++) {
    if (msg[i] != res[i]) {
      log_info("byte %d: msg: %d, res: %d\n", msg[i], res[i]);
      break;
    } else {
      log_info("received: %d\n", res[i]);
    }
  }

  conn->Shutdown();
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
