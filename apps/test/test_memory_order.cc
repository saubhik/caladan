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

std::atomic<bool> x = ATOMIC_VAR_INIT(false);
std::atomic<bool> y = ATOMIC_VAR_INIT(false);
std::atomic<int> z = ATOMIC_VAR_INIT(0);

void write_x() { x.store(true, std::memory_order_seq_cst); }

void write_y() { y.store(true, std::memory_order_seq_cst); }

// z == 0 only if x=true, y=false
void read_x_then_y() {
  while (!x.load(std::memory_order_seq_cst))
    ;
  if (y.load(std::memory_order_seq_cst)) ++z;
}

// z == 0 only if x=false, y=true
void read_y_then_x() {
  while (!y.load(std::memory_order_seq_cst))
    ;
  if (x.load(std::memory_order_seq_cst)) ++z;
}

void MainHandler(void *arg) {
  auto th1 = rt::Thread(write_x);
  auto th2 = rt::Thread(write_y);
  auto th3 = rt::Thread(read_x_then_y);
  auto th4 = rt::Thread(read_y_then_x);

  th1.Join();
  th2.Join();
  th3.Join();
  th4.Join();

  // assert(z.load() != 0);
  // z==0 will never happen
  log_info("the value of z is %d", z.load());
}

}  // namespace

int main(int argc, char *argv[]) {
  int ret;

  if (argc != 2) {
    std::cerr << "usage: [config_file]" << std::endl;
    return -EINVAL;
  }

  ret = runtime_init(argv[1], MainHandler, NULL);
  if (ret) {
    printf("failed to start runtime\n");
    return ret;
  }

  return 0;
}
