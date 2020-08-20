/******************************************************************************
 *                    _   _____   __________                                  *
 *                   | | / / _ | / __/_  __/     Visibility                   *
 *                   | |/ / __ |_\ \  / /          Across                     *
 *                   |___/_/ |_/___/ /_/       Space and Time                 *
 *                                                                            *
 * This file is part of VAST. It is subject to the license terms in the       *
 * LICENSE file found in the top-level directory of this distribution and at  *
 * http://vast.io/license. No part of VAST, including this file, may be       *
 * copied, modified, propagated, or distributed except according to the terms *
 * contained in the LICENSE file.                                             *
 ******************************************************************************/

#include "vast/detail/posix.hpp"

#include "vast/config.hpp"
#include "vast/detail/assert.hpp"
#include "vast/detail/raise_error.hpp"
#include "vast/logger.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

namespace vast {
namespace detail {

int uds_listen(const std::string& path) {
  int fd;
  if ((fd = ::socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    return fd;
  ::sockaddr_un un;
  std::memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  std::strncpy(un.sun_path, path.data(), sizeof(un.sun_path) - 1);
  ::unlink(path.c_str()); // Always remove previous socket file.
  auto sa = reinterpret_cast<sockaddr*>(&un);
  if (::bind(fd, sa, sizeof(un)) < 0 || ::listen(fd, 10) < 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

int uds_accept(int socket) {
  if (socket < 0)
    return -1;
  int fd;
  ::sockaddr_un un;
  socklen_t size = sizeof(un);
  if ((fd = ::accept(socket, reinterpret_cast<::sockaddr*>(&un), &size)) < 0)
    return -1;
  return fd;
}

VAST_DIAGNOSTIC_PUSH
#if VAST_GCC
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

int uds_connect(const std::string& path, socket_type type) {
  int fd;
  switch (type) {
    case socket_type::stream:
    case socket_type::fd:
      if ((fd = ::socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return fd;
      break;
    case socket_type::datagram:
      if ((fd = ::socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        return fd;
      ::sockaddr_un clt;
      std::memset(&clt, 0, sizeof(clt));
      clt.sun_family = AF_UNIX;
      auto client_path = path + "-client";
      std::strncpy(clt.sun_path, client_path.data(), sizeof(clt.sun_path) - 1);
      ::unlink(client_path.c_str()); // Always remove previous socket file.
      if (::bind(fd, reinterpret_cast<sockaddr*>(&clt), sizeof(clt)) < 0) {
        VAST_WARNING(__func__, "failed in bind:", ::strerror(errno));
        return -1;
      }
      break;
  }
  ::sockaddr_un srv;
  std::memset(&srv, 0, sizeof(srv));
  srv.sun_family = AF_UNIX;
  std::strncpy(srv.sun_path, path.data(), sizeof(srv.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&srv), sizeof(srv)) < 0) {
    if (!(type == socket_type::datagram && errno == ENOENT)) {
      VAST_WARNING(__func__, "failed in connect:", ::strerror(errno));
      return -1;
    }
  }
  return fd;
}

VAST_DIAGNOSTIC_POP

// On Mac OS, CMSG_SPACE is for some reason not a constant expression.
VAST_DIAGNOSTIC_PUSH
VAST_DIAGNOSTIC_IGNORE_VLA_EXTENSION

bool uds_send_fd(int socket, int fd) {
  if (socket < 0)
    return -1;
  char dummy = '*';
  ::iovec iov[1];
  iov[0].iov_base = &dummy;
  iov[0].iov_len = sizeof(dummy);
  char ctrl_buf[CMSG_SPACE(sizeof(int))];
  std::memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int)));
  // Setup message header.
  ::msghdr m;
  std::memset(&m, 0, sizeof(struct msghdr));
  m.msg_name = nullptr;
  m.msg_namelen = 0;
  m.msg_iov = iov;
  m.msg_iovlen = 1;
  m.msg_controllen = CMSG_SPACE(sizeof(int));
  m.msg_control = ctrl_buf;
  // Setup control message header.
  auto c = CMSG_FIRSTHDR(&m);
  c->cmsg_level = SOL_SOCKET;
  c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN(sizeof(int));
  *reinterpret_cast<int*>(CMSG_DATA(c)) = fd;
  // Send a message.
  return ::sendmsg(socket, &m, 0) > 0;
}

int uds_recv_fd(int socket) {
  if (socket < 0)
    return -1;
  char ctrl_buf[CMSG_SPACE(sizeof(int))];
  std::memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int)));
  char dummy;
  ::iovec iov[1];
  iov[0].iov_base = &dummy;
  iov[0].iov_len = sizeof(dummy);
  // Setup message header.
  ::msghdr m;
  std::memset(&m, 0, sizeof(struct msghdr));
  m.msg_name = nullptr;
  m.msg_namelen = 0;
  m.msg_control = ctrl_buf;
  m.msg_controllen = CMSG_SPACE(sizeof(int));
  m.msg_iov = iov;
  m.msg_iovlen = 1;
  // Receive a message.
  if (::recvmsg(socket, &m, 0) <= 0)
    return -1;
  // Iterate over control message headers until we find the descriptor.
  for (auto c = CMSG_FIRSTHDR(&m); c != nullptr; c = CMSG_NXTHDR(&m, c))
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
      return *reinterpret_cast<int*>(CMSG_DATA(c));
  return -1;
}

VAST_DIAGNOSTIC_POP
int unix_domain_socket::listen(const std::string& path) {
  return detail::uds_listen(path);
}

unix_domain_socket unix_domain_socket::accept(const std::string& path) {
  auto server = detail::uds_listen(path);
  if (server != -1)
    return unix_domain_socket{detail::uds_accept(server)};
  return unix_domain_socket{};
}

unix_domain_socket
unix_domain_socket::connect(const std::string& path, socket_type type) {
  return unix_domain_socket{detail::uds_connect(path, type)};
}

unix_domain_socket::unix_domain_socket(int fd) : fd_{fd} {
}

unix_domain_socket::operator bool() const {
  return fd_ != -1;
}

bool unix_domain_socket::send_fd(int fd) {
  VAST_ASSERT(*this);
  return detail::uds_send_fd(fd_, fd);
}

int unix_domain_socket::recv_fd() {
  VAST_ASSERT(*this);
  return detail::uds_recv_fd(fd_);
}

int unix_domain_socket::fd() const {
  return fd_;
}

namespace {

bool make_nonblocking(int fd, bool flag) {
  auto flags = ::fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return false;
  flags = flag ? flags | O_NONBLOCK : flags & ~O_NONBLOCK;
  return ::fcntl(fd, F_SETFL, flags) != -1;
}

} // namespace <anonymous>

bool make_nonblocking(int fd) {
  return make_nonblocking(fd, true);
}

bool make_blocking(int fd) {
  return make_nonblocking(fd, false);
}

bool poll(int fd, int usec) {
  fd_set rdset;
  FD_ZERO(&rdset);
  FD_SET(fd, &rdset);
  timeval timeout{0, usec};
  auto rc = ::select(fd + 1, &rdset, nullptr, nullptr, &timeout);
  if (rc < 0) {
    switch (rc) {
      default:
        VAST_RAISE_ERROR(std::logic_error, "unhandled select() error");
      case EINTR:
      case ENOMEM:
        return false;
    }
  }
  return FD_ISSET(fd, &rdset);
}

bool close(int fd) {
  int result;
  do {
    result = ::close(fd);
  } while (result < 0 && errno == EINTR);
  return result == 0;
}

bool read(int fd, void* buffer, size_t bytes, size_t* got) {
  ssize_t taken;
  do {
    taken = ::read(fd, buffer, bytes);
  } while (taken < 0 && errno == EINTR);
  if (taken <= 0) // EOF == 0, error == -1
    return false;
  if (got)
    *got = static_cast<size_t>(taken);
  return true;
}

bool write(int fd, const void* buffer, size_t bytes, size_t* put) {
  auto total = size_t{0};
  auto buf = reinterpret_cast<const uint8_t*>(buffer);
  while (total < bytes) {
    ssize_t written;
    do {
      written = ::write(fd, buf + total, bytes - total);
    } while (written < 0 && errno == EINTR);
    if (written <= 0)
      return false;
    total += static_cast<size_t>(written);
  }
  if (put)
    *put = total;
  return true;
}

bool seek(int fd, size_t bytes) {
  return ::lseek(fd, bytes, SEEK_CUR) != -1;
}

} // namespace detail
} // namespace vast
