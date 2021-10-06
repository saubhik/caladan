// thread.h - Support for creating and managing threads

#pragma once

extern "C" {
#include <base/assert.h>
#include <base/thread.h>
#include <runtime/sync.h>
#include <runtime/timer.h>
}

#include <chrono>
#include <functional>

namespace rt {
namespace thread_internal {

struct join_data {
  join_data(std::function<void()>&& func);
  join_data(const std::function<void()>& func);

  spinlock_t lock_;
  thread_id_t id_;
  bool done_;
  thread_t* waiter_;
  std::function<void()> func_;
};

extern void ThreadTrampoline(void* arg);
extern void ThreadTrampolineWithJoin(void* arg);

}  // namespace thread_internal

// Spawns a new thread by copying.
inline void Spawn(const std::function<void()>& func) {
  void* buf;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new (buf) std::function<void()>(func);
  thread_ready(th);
}

// Spawns a new thread by moving.
inline void Spawn(std::function<void()>&& func) {
  void* buf;
  thread_t* th = thread_create_with_buf(thread_internal::ThreadTrampoline, &buf,
                                        sizeof(std::function<void()>));
  if (unlikely(!th)) BUG();
  new (buf) std::function<void()>(std::move(func));
  thread_ready(th);
}

// Called from a running thread to exit.
inline void Exit(void) { thread_exit(); }

// Called from a running thread to yield.
inline void Yield(void) { thread_yield(); }

// A C++11 style thread class
class Thread {
 public:
  // boilerplate constructors.
  Thread() : join_data_(nullptr) {}
  ~Thread();

  // disable copy.
  Thread(const Thread&) = delete;
  Thread& operator=(const Thread&) = delete;

  // Move support.
  Thread(Thread&& t) : join_data_(t.join_data_) { t.join_data_ = nullptr; }
  Thread& operator=(Thread&& t) {
    join_data_ = t.join_data_;
    t.join_data_ = nullptr;
    return *this;
  }

  // Spawns a thread by copying a std::function.
  Thread(const std::function<void()>& func);

  // Spawns a thread by moving a std::function.
  Thread(std::function<void()>&& func);

  // Waits for the thread to exit.
  void Join();

  // Detaches the thread, indicating it won't be joined in the future.
  void Detach();

  typedef thread_id_t native_handle_type;

  // Similar to std::thread::id.
  class Id {
    native_handle_type thread_id_;

   public:
    Id() noexcept : thread_id_(-1) {}
    explicit Id(native_handle_type id) : thread_id_(id) {}

   private:
    friend class Thread;
    friend class std::hash<Thread::Id>;

    friend bool operator==(Thread::Id x, Thread::Id y) noexcept;
    friend bool operator<(Thread::Id x, Thread::Id y) noexcept;

    template <class _CharT, class _Traits>
    friend std::basic_ostream<_CharT, _Traits>& operator<<(
        std::basic_ostream<_CharT, _Traits>& out, Thread::Id id);
  };

  Thread::Id GetId() const noexcept { return id_; }

  // Similar to std::thread::hardware_concurrency().
  static unsigned int HardwareConcurrency() noexcept { return nrks; }

 private:
  Id id_;
  thread_internal::join_data* join_data_;
};

inline bool operator==(Thread::Id x, Thread::Id y) noexcept {
  return x.thread_id_ == y.thread_id_;
}

inline bool operator<(Thread::Id x, Thread::Id y) noexcept {
  return x.thread_id_ < y.thread_id_;
}

inline bool operator<=(Thread::Id x, Thread::Id y) noexcept { return !(y < x); }

inline bool operator>(Thread::Id x, Thread::Id y) noexcept { return y < x; }

inline bool operator>=(Thread::Id x, Thread::Id y) noexcept { return !(x < y); }

template <class _CharT, class _Traits>
inline std::basic_ostream<_CharT, _Traits>& operator<<(
    std::basic_ostream<_CharT, _Traits>& out, Thread::Id id) {
  if (id == Thread::Id())
    return out << "Thread::Id of a non-executing thread";
  else
    return out << id.thread_id_;
}

// Called from a running thread. Similar to std::this_thread::get_id()
inline Thread::Id GetId() noexcept {
  return Thread::Id(get_uthread_specific());
}

// Called from a running thread. Similar to std::this_thread::sleep_for
template <typename _Rep, typename _Period>
inline void SleepFor(const std::chrono::duration<_Rep, _Period>& time) {
  if (time <= time.zero()) return;
  auto micros =
      std::chrono::duration_cast<std::chrono::microseconds>(time).count();
  timer_sleep(static_cast<uint64_t>(micros));
}

}  // namespace rt

// Inject custom specialization of std::hash in namespace std.
namespace std {

template <>
struct hash<rt::Thread::Id> : public __hash_base<size_t, rt::Thread::Id> {
  size_t operator()(const rt::Thread::Id& id) const noexcept {
    return _Hash_impl::hash(id.thread_id_);
  }
};

}  // namespace std
