#pragma once

#include <sys/socket.h>

#include <quic/lib/network_socket.h>

namespace quic {

namespace netops {

NetworkSocket accept(NetworkSocket s, sockaddr* addr, socklen_t* addrlen);
int bind(NetworkSocket s, const sockaddr* name, socklen_t namelen);
int close(NetworkSocket s);
int connect(NetworkSocket s, const sockaddr* name, socklen_t namelen);
int getpeername(NetworkSocket s, sockaddr* name, socklen_t* namelen);
int getsockname(NetworkSocket s, sockaddr* name, socklen_t* namelen);
int listen(NetworkSocket s, int backlog);
ssize_t recv(NetworkSocket s, void* buf, size_t len, int flag);
ssize_t recvfrom(NetworkSocket s, void* buf, size_t len, int flags,
                 sockaddr* from, socklen_t* fromlen);
ssize_t recvmsg(NetworkSocket s, msghdr* message, int flags);
int recvmmsg(NetworkSocket s, mmsghdr* msgvec, unsigned int vlen,
             unsigned int flags, timespec* timeout);
ssize_t send(NetworkSocket s, const void* buf, size_t len, int flags);
ssize_t sendto(NetworkSocket s, const void* buf, size_t len, int flags,
               const sockaddr* to, socklen_t tolen);
ssize_t sendmsg(NetworkSocket socket, const msghdr* message, int flags);
int sendmmsg(NetworkSocket socket, mmsghdr* msgvec, unsigned int vlen,
             int flags);
int shutdown(NetworkSocket s, int how);
NetworkSocket socket(int af, int type, int protocol);

}  // namespace netops

}  // namespace quic
