/*
 * test_atomic.cc - tests support of std lib atomics
 */

extern "C" {
#include <base/log.h>
}

#include "runtime.h"
#include "sync.h"
#include "thread.h"
#include "timer.h"

#include <atomic>
#include <iostream>

namespace {

int threads;

void MainHandler(void *arg) {
  rt::WaitGroup wg(threads);
  std::atomic<bool> ready(false);
  std::atomic_flag winner = ATOMIC_FLAG_INIT;

  for (int i = 0; i < threads; ++i) {
    rt::Spawn([&, i]() {
      while (!ready) {
        rt::Yield();
      }
      rt::Delay(10000);
      if (!winner.test_and_set()) {
        log_info("thread #%d won!", i);
      }
      wg.Done();
    });
  }

  ready = true;

  wg.Wait();
  log_info("test complete");
}

}  // namespace

int main(int argc, char *argv[]) {
  int ret;

  if (argc != 3) {
    std::cerr << "usage: [config_file] [#threads]" << std::endl;
    return -EINVAL;
  }

  threads = std::stoi(argv[2], nullptr, 0);

  ret = runtime_init(argv[1], MainHandler, NULL);
  if (ret) {
    printf("failed to start runtime\n");
    return ret;
  }

  return 0;
}
