#pragma once

#include <stdexcept>
#include <string>

namespace quic {

class AsyncSocketException : public std::runtime_error {
 public:
  enum AsyncSocketExceptionType {
    UNKNOWN = 0,
    NOT_OPEN = 1,
  };

  AsyncSocketException(AsyncSocketExceptionType type,
                       const std::string& message, int errno_copy = 0)
      : std::runtime_error(GetMessage(type, message, errno_copy)),
        type_(type),
        errno_(errno_copy) {}

  AsyncSocketExceptionType GetType() const noexcept { return type_; }

  int getErrno() const noexcept { return errno_; }

 protected:
  static std::string GetExceptionTypeString(AsyncSocketExceptionType type);

  // Return a message based on the input.
  static std::string GetMessage(AsyncSocketExceptionType type,
                                const std::string& message, int errno_copy);

  // Error code.
  AsyncSocketExceptionType type_;

  // A copy of the errno.
  int errno_;
};

}  // namespace quic
