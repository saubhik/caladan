extern "C" {
#include <base/log.h>
#include <net/ip.h>
#include <unistd.h>
}

#include "net.h"
#include "runtime.h"
#include "sync.h"
#include "synthetic_worker.h"
#include "thread.h"
#include "timer.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace std::chrono;
using sec = duration<double, std::micro>;

// <- ARGUMENTS FOR EXPERIMENT ->
// the number of worker threads to spawn.
int threads;
// the remote UDP address of the server.
netaddr raddr;

constexpr uint64_t kNetbenchPort = 8001;
constexpr uint64_t kNetbenchPort2 = 8002;

void receive_callback(void * q) {
  int pp;
  netaddr raddr1;
  printf("callback made\n");

  // A single callback might be made after multiple triggers,
  // make sure to drain the queue
  while (true) {
    ssize_t ret = reinterpret_cast<rt::UdpConn*>(q)->ReadFrom(&pp,
                                                  sizeof(pp), &raddr1);
    if (ret != static_cast<ssize_t>(sizeof(pp))) {
      printf("reading nonblocked in callback\n");
      return;
    }
    printf("still in callback\n");
    pp++;
    ret = reinterpret_cast<rt::UdpConn*>(q)->WriteTo(&pp, sizeof(int),&raddr1);
    if (ret != static_cast<ssize_t>(sizeof(int)))
      panic("write failed, ret = %ld", ret);
  }
}

void ServerHandler(void *arg) {
  rt::UdpConn* q = rt::UdpConn::Listen({0, kNetbenchPort});
  if (q == nullptr) panic("couldn't listen for connections");

  rt::EventLoop* evl = rt::EventLoop::CreateWaiter();
  if (evl == nullptr) panic("couldn't listen for connections");

  rt::Event* evt = rt::Event::CreateEvent();
  if (evt == nullptr) panic("couldn't listen for connections");

  evl->AddEvent(evt, q, &receive_callback, q);
  q->SetNonblocking(true);

  while (true) {
    evl->LoopCbOnce();
  }
}

struct work_unit {
  double start_us, work_us, duration_us;
  uint64_t tsc;
  uint32_t cpu;
};


void ClientWorker(
    rt::UdpConn *c, rt::WaitGroup *starter) {
  std::vector<time_point<steady_clock>> timings;

  // Start the receiver thread.
  auto th = rt::Thread([&] {
    int rp;

    while (true) {
      ssize_t ret = c->Read(&rp, sizeof(rp));
      if (ret != static_cast<ssize_t>(sizeof(rp))) {
        if (ret == 0 || ret < 0) break;
        panic("read failed, ret = %ld", ret);
      }
      printf("got result %d \n", rp);
    }
  });

  // Synchronized start of load generation.
  starter->Done();
  starter->Wait();

  int p = 100;

  for (unsigned int i = 0; i < 10; ++i) {
    ssize_t ret = c->Write(&p, sizeof(int));
    if (ret != static_cast<ssize_t>(sizeof(int)))
      panic("write failed, ret = %ld", ret);

    p++;
    rt::Sleep(1 * rt::kSeconds);
  }

  c->Shutdown();
  th.Join();
}

void RunExperiment(
    int threads_l, double *reqs_per_sec, double *cpu_usage) {
  // Create one TCP connection per thread.
  std::vector<std::unique_ptr<rt::UdpConn>> conns;
  for (int i = 0; i < threads_l; ++i) {
    std::unique_ptr<rt::UdpConn> outc(rt::UdpConn::Dial({0, 0}, raddr));
    if (unlikely(outc == nullptr)) panic("couldn't connect to raddr.");
    conns.emplace_back(std::move(outc));
  }

  // Launch a worker thread for each connection.
  rt::WaitGroup starter(threads + 1);
  std::vector<rt::Thread> th;
  for (int i = 0; i < threads; ++i) {
    th.emplace_back(rt::Thread([&, i] {
      ClientWorker(conns[i].get(), &starter);
    }));
  }

  // Give the workers time to initialize, then start recording.
  starter.Done();
  starter.Wait();

  // Wait for the workers to finish.
  for (auto &t : th) t.Join();

  // Close the connections.
  for (auto &c : conns) c->Shutdown();

}


void SteadyStateExperiment(int threads_l) {
  double rps, cpu_usage;
  RunExperiment(threads_l, &rps, &cpu_usage);
}

void ClientHandler(void *arg) {
  SteadyStateExperiment(threads);
}

int StringToAddr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;

  if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) return -EINVAL;

  *addr = MAKE_IP_ADDR(a, b, c, d);
  return 0;
}

std::vector<std::string> split(const std::string &text, char sep) {
  std::vector<std::string> tokens;
  std::string::size_type start = 0, end = 0;
  while ((end = text.find(sep, start)) != std::string::npos) {
    tokens.push_back(text.substr(start, end - start));
    start = end + 1;
  }
  tokens.push_back(text.substr(start));
  return tokens;
}


}  // anonymous namespace

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
  } else if (cmd.compare("client") == 0) {
    std::cerr << "invalid command: " << cmd << std::endl;
    return -EINVAL;
  }

  if (argc < 5) {
    std::cerr << "usage: [cfg_file] client [#threads] [remote_ip]"
              << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[3], nullptr, 0);

  ret = StringToAddr(argv[4], &raddr.ip);
  if (ret) return -EINVAL;
  raddr.port = kNetbenchPort;

  ret = runtime_init(argv[1], ClientHandler, NULL);
  if (ret) {
    printf("failed to start runtime\n");
    return ret;
  }

  return 0;
}
