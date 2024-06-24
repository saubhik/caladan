#include <quic/lib/async_socket_exception.h>

#include <cerrno>
#include <cstring>

namespace quic {

std::string AsyncSocketException::GetExceptionTypeString(
    AsyncSocketExceptionType type) {
  switch (type) {
    case UNKNOWN:
      return "Unknown async socked exception";
    case NOT_OPEN:
      return "Socket not open";
    default:
      return "Invalid exception type";
  }
}

std::string AsyncSocketException::GetMessage(AsyncSocketExceptionType type,
                                             const std::string& message,
                                             int errno_copy) {
  if (errno != 0) {
    return "AsyncSocketException: " + message +
           ", type = " + GetExceptionTypeString(type) +
           ", errno = " + std::strerror(errno_copy);
  } else {
    return "AsyncSocketException: " + message +
           ", type = " + GetExceptionTypeString(type);
  }
}

}  // namespace quic
