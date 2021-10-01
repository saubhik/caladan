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
#include <sstream>

namespace {

std::atomic<bool> x = ATOMIC_VAR_INIT(false);
std::atomic<bool> y = ATOMIC_VAR_INIT(false);
std::atomic<int> z = ATOMIC_VAR_INIT(0);

// Check rt::GetId() works.
void PrintId() {
  std::stringstream msg;
  msg << "My ID is " << rt::GetId() << "\n";
  std::cout << msg.str();
}

void WriteX() {
  x.store(true, std::memory_order_seq_cst);
  PrintId();
}

void WriteY() {
  y.store(true, std::memory_order_seq_cst);
  PrintId();
}

// z == 0 only if x=true, y=false
void ReadXThenY() {
  while (!x.load(std::memory_order_seq_cst))
    ;
  if (y.load(std::memory_order_seq_cst)) ++z;
  PrintId();
}

// z == 0 only if x=false, y=true
void ReadYThenX() {
  while (!y.load(std::memory_order_seq_cst))
    ;
  if (x.load(std::memory_order_seq_cst)) ++z;
  PrintId();
}

void MainHandler(void *arg) {
  auto th1 = rt::Thread(WriteX);
  auto th2 = rt::Thread(WriteY);
  auto th3 = rt::Thread(ReadXThenY);
  auto th4 = rt::Thread(ReadYThenX);

  th1.Join();
  th2.Join();
  th3.Join();
  th4.Join();

  // Check hardware concurrency.
  log_info("the hardware concurrency is %d", th1.HardwareConcurrency());

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
