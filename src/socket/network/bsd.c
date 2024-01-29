#define __APPLE_USE_RFC_3542

#include "v_socket.h"
#include "../internal/internal.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

/* Internal structure of packet buffer */
struct v_internal_udp_packet_buffer {
#if defined(_WIN32) || defined(__APPLE__)
    char *buf[VENOK_UDP_MAX_NUM];
    size_t len[VENOK_UDP_MAX_NUM];
    struct sockaddr_storage addr[VENOK_UDP_MAX_NUM];
#else
    struct mmsghdr msgvec[VENOK_UDP_MAX_NUM];
    struct iovec iov[VENOK_UDP_MAX_NUM];
    struct sockaddr_storage addr[VENOK_UDP_MAX_NUM];
    char control[VENOK_UDP_MAX_NUM][256];
#endif
};

/* We need to emulate sendmmsg, recvmmsg on platform who don't have it */
int bsd_sendmmsg(VENOK_SOCKET_DESCRIPTOR fd, void *msgvec, unsigned int vlen, int flags) {
#if defined(__APPLE__)
    struct mmsghdr {
        struct msghdr msg_hdr;  /* Message header */
        unsigned int  msg_len;  /* Number of bytes transmitted */
    };

    struct mmsghdr *hdrs = (struct mmsghdr *) msgvec;

    for (int i = 0; i < vlen; i++) {
        int ret = sendmsg(fd, &hdrs[i].msg_hdr, flags);
        if (ret == -1) {
            if (i) return i;
            return -1;
        } else hdrs[i].msg_len = ret;
    }

    return vlen;

#elif defined(_WIN32)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) msgvec;

    /* Let's just use sendto here */
    /* Winsock does not have sendmsg, while macOS has, however, we simply use sendto since both macOS and Winsock has it.
     * Besides, you should use Linux either way to get the best performance with the sendmmsg */

    // while we do not get error, send next
    for (int i = 0; i < VENOK_UDP_MAX_NUM; i++) {
        // need to support ipv6 addresses also!
        int ret = sendto(fd, packet_buffer->buf[i], packet_buffer->len[i],
                         flags, (struct sockaddr *) &packet_buffer->addr[i],
                         sizeof(struct sockaddr_in));

        // If we fail then we need to buffer up, no that's not our problem
        // We do need to register poll out though and have a callback for it
        if (ret == -1) return i;
    }

    return VENOK_UDP_MAX_NUM; // one message
#else
    return sendmmsg(fd, (struct mmsghdr *)msgvec, vlen, flags | MSG_NOSIGNAL);
#endif
}

int bsd_recvmmsg(VENOK_SOCKET_DESCRIPTOR fd, void *msgvec, unsigned int vlen, int flags, void *timeout) {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) msgvec;

    for (int i = 0; i < VENOK_UDP_MAX_NUM; i++) {
        socklen_t addr_len = sizeof(struct sockaddr_storage);
        int ret = recvfrom(fd, packet_buffer->buf[i], VENOK_UDP_MAX_SIZE, flags, (struct sockaddr *) &packet_buffer->addr[i], &addr_len);

        if (ret == -1) return i;

        packet_buffer->len[i] = ret;
    }

    return VENOK_UDP_MAX_NUM;
#else
    // We need to set controllen for ip packet
    for (int i = 0; i < vlen; i++) {
        ((struct mmsghdr *)msgvec)[i].msg_hdr.msg_controllen = 256;
    }

    return recvmmsg(fd, (struct mmsghdr *)msgvec, vlen, flags, 0);
#endif
}

// This one is needed for knowing the destination addr of udp packet
// an udp socket can only bind to one port, and that port never changes
// This function returns ONLY the IP address, not any port
int bsd_udp_packet_buffer_local_ip(void *msgvec, int index, char *ip) {
#if defined(_WIN32) || defined(__APPLE__)
    return 0; // not supported
#else
    struct msghdr *mh = &((struct mmsghdr *) msgvec)[index].msg_hdr;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(mh); cmsg != NULL; cmsg = CMSG_NXTHDR(mh, cmsg)) {
        // ipv6 or ipv4
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cmsg);
            memcpy(ip, &pi->ipi_addr, 4);
            return 4;
        }

        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *pi6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            memcpy(ip, &pi6->ipi6_addr, 16);
            return 16;
        }
    }

    return 0; // no length
#endif
}

char *bsd_udp_packet_buffer_peer(void *msgvec, int index) {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) msgvec;
    return (char *) &packet_buffer->addr[index];
#else
    return ((struct mmsghdr *) msgvec)[index].msg_hdr.msg_name;
#endif
}

char *bsd_udp_packet_buffer_payload(void *msgvec, int index) {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) msgvec;
    return packet_buffer->buf[index];
#else
    return ((struct mmsghdr *) msgvec)[index].msg_hdr.msg_iov[0].iov_base;
#endif
}

int bsd_udp_packet_buffer_payload_length(void *msgvec, int index) {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) msgvec;
    return packet_buffer->len[index];
#else
    return ((struct mmsghdr *) msgvec)[index].msg_len;
#endif
}

void bsd_udp_buffer_set_packet_payload(struct v_udp_packet_buffer *send_buf, int index, int offset,
                                       void *payload, int length, void *peer_addr) {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *packet_buffer = (struct v_internal_udp_packet_buffer *) send_buf;

    memcpy(packet_buffer->buf[index], payload, length);
    memcpy(&packet_buffer->addr[index], peer_addr, sizeof(struct sockaddr_storage));

    packet_buffer->len[index] = length;
#else
    struct mmsghdr *ss = (struct mmsghdr *) send_buf;

    // copy the peer address
    memcpy(ss[index].msg_hdr.msg_name, peer_addr, /*ss[index].msg_hdr.msg_namelen*/ sizeof(struct sockaddr_in));

    // set control length to 0
    ss[index].msg_hdr.msg_controllen = 0;

    // copy the payload
    ss[index].msg_hdr.msg_iov->iov_len = length + offset;

    memcpy(((char *) ss[index].msg_hdr.msg_iov->iov_base) + offset, payload, length);
#endif
}

/* The maximum UDP payload size is 64kb, but in IPV6 you can have jumbo packets larger than so.
 * We do not support those jumbo packets currently, but will safely ignore them.
 * Any sane sender would assume we don't support them if we consistently drop them.
 * Therefore, an udp_packet_buffer will be 64 MB in size (64kb * 1024). */
void *bsd_create_udp_packet_buffer() {
#if defined(_WIN32) || defined(__APPLE__)
    struct v_internal_udp_packet_buffer *b = malloc(sizeof(struct v_internal_udp_packet_buffer) + VENOK_UDP_MAX_SIZE * VENOK_UDP_MAX_NUM);

    for (int i = 0; i < VENOK_UDP_MAX_NUM; i++) {
        b->buf[i] = ((char *) b) + sizeof(struct v_internal_udp_packet_buffer) + VENOK_UDP_MAX_SIZE * i;
    }

    return (struct v_udp_packet_buffer *) b;
#else
    /* Allocate 64kb times 1024 */
    struct v_internal_udp_packet_buffer *b = malloc(sizeof(struct v_internal_udp_packet_buffer) + VENOK_UDP_MAX_SIZE * VENOK_UDP_MAX_NUM);

    for (int n = 0; n < VENOK_UDP_MAX_NUM; ++n) {
        b->iov[n].iov_base = &((char *) (b + 1))[n * VENOK_UDP_MAX_SIZE];
        b->iov[n].iov_len = VENOK_UDP_MAX_SIZE;

        b->msgvec[n].msg_hdr = (struct msghdr) {
            .msg_name       = &b->addr,
            .msg_namelen    = sizeof (struct sockaddr_storage),

            .msg_iov        = &b->iov[n],
            .msg_iovlen     = 1,

            .msg_control    = b->control[n],
            .msg_controllen = 256,
        };
    }

    return (struct v_udp_packet_buffer *) b;
#endif
}

/* TCP Layer */
VENOK_SOCKET_DESCRIPTOR apple_no_sigpipe(VENOK_SOCKET_DESCRIPTOR fd) {
#ifdef __APPLE__
    if (fd != VENOK_SOCKET_ERROR) {
        int no_sigpipe = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *) &no_sigpipe, sizeof(int));
    }
#endif
    return fd;
}

VENOK_SOCKET_DESCRIPTOR bsd_set_nonblocking(VENOK_SOCKET_DESCRIPTOR fd) {
#ifdef _WIN32
    /* Libuv will set windows sockets as non-blocking */
#else
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif
    return fd;
}

void bsd_socket_nodelay(VENOK_SOCKET_DESCRIPTOR fd, int enabled) {
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *) &enabled, sizeof(enabled));
}

void bsd_socket_flush(VENOK_SOCKET_DESCRIPTOR fd) {
    // Linux TCP_CORK has the same underlying corking mechanism as with MSG_MORE
#ifdef TCP_CORK
    int enabled = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, (void *) &enabled, sizeof(int));
#endif
}

VENOK_SOCKET_DESCRIPTOR bsd_create_socket(int domain, int type, int protocol) {
    // returns INVALID_SOCKET on error
    int flags = 0;
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
#endif
    VENOK_SOCKET_DESCRIPTOR created_fd = socket(domain, type | flags, protocol);
    return bsd_set_nonblocking(apple_no_sigpipe(created_fd));
}

void bsd_close_socket(VENOK_SOCKET_DESCRIPTOR fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

void bsd_shutdown_socket(VENOK_SOCKET_DESCRIPTOR fd) {
#ifdef _WIN32
    shutdown(fd, SD_SEND);
#else
    shutdown(fd, SHUT_WR);
#endif
}

void bsd_shutdown_socket_read(VENOK_SOCKET_DESCRIPTOR fd) {
#ifdef _WIN32
    shutdown(fd, SD_RECEIVE);
#else
    shutdown(fd, SHUT_RD);
#endif
}

void internal_finalize_bsd_addr(struct bsd_addr *addr) {
    // Parse, so to speak, the address
    if (addr->mem.ss_family == AF_INET6) {
        addr->ip = (char *) &((struct sockaddr_in6 *) addr)->sin6_addr;
        addr->ip_length = sizeof(struct in6_addr);
        addr->port = ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
    } else if (addr->mem.ss_family == AF_INET) {
        addr->ip = (char *) &((struct sockaddr_in *) addr)->sin_addr;
        addr->ip_length = sizeof(struct in_addr);
        addr->port = ntohs(((struct sockaddr_in *) addr)->sin_port);
    } else {
        addr->ip_length = 0;
        addr->port = -1;
    }
}

int bsd_local_addr(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr) {
    addr->len = sizeof(addr->mem);
    if (getsockname(fd, (struct sockaddr *) &addr->mem, &addr->len)) return -1;
    internal_finalize_bsd_addr(addr);
    return 0;
}

int bsd_remote_addr(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr) {
    addr->len = sizeof(addr->mem);
    if (getpeername(fd, (struct sockaddr *) &addr->mem, &addr->len)) return -1;
    internal_finalize_bsd_addr(addr);
    return 0;
}

char *bsd_addr_get_ip(struct bsd_addr *addr) {
    return addr->ip;
}

int bsd_addr_get_ip_length(struct bsd_addr *addr) {
    return addr->ip_length;
}

int bsd_addr_get_port(struct bsd_addr *addr) {
    return addr->port;
}

// Called by dispatch_ready_poll
VENOK_SOCKET_DESCRIPTOR bsd_accept_socket(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr) {
    VENOK_SOCKET_DESCRIPTOR accepted_fd;
    addr->len = sizeof(addr->mem);

#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    // Linux, FreeBSD
    accepted_fd = accept4(fd, (struct sockaddr *) addr, &addr->len, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
    // Windows, OS X
    accepted_fd = accept(fd, (struct sockaddr *) addr, &addr->len);
#endif

    /* We cannot rely on addr since it is not initialized if failed */
    if (accepted_fd == VENOK_SOCKET_ERROR) return VENOK_SOCKET_ERROR;

    internal_finalize_bsd_addr(addr);

    return bsd_set_nonblocking(apple_no_sigpipe(accepted_fd));
}

int bsd_recv(VENOK_SOCKET_DESCRIPTOR fd, void *buf, int length, int flags) {
    return recv(fd, buf, length, flags);
}

#if !defined(_WIN32)
#include <sys/uio.h>

int bsd_write2(VENOK_SOCKET_DESCRIPTOR fd, const char *header, int header_length, const char *payload, int payload_length) {
    struct iovec chunks[2];

    chunks[0].iov_base = (char *)header;
    chunks[0].iov_len = header_length;
    chunks[1].iov_base = (char *)payload;
    chunks[1].iov_len = payload_length;

    return writev(fd, chunks, 2);
}
#else
int bsd_write2(VENOK_SOCKET_DESCRIPTOR fd, const char *header, int header_length, const char *payload, int payload_length) {
    int written = bsd_send(fd, header, header_length, 0);
    if (written == header_length) {
        int second_write = bsd_send(fd, payload, payload_length, 0);
        if (second_write > 0) written += second_write;
    }
    return written;
}
#endif

int bsd_send(VENOK_SOCKET_DESCRIPTOR fd, const char *buf, int length, int msg_more) {
    // MSG_MORE (Linux), MSG_PARTIAL (Windows), TCP_NOPUSH (BSD)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef MSG_MORE
    // for Linux we do not want signals
    return send(fd, buf, length, ((msg_more != 0) * MSG_MORE) | MSG_NOSIGNAL | MSG_DONTWAIT);
#else
    // use TCP_NOPUSH
    return send(fd, buf, length, MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
}

int bsd_would_block() {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EWOULDBLOCK;// || errno == EAGAIN;
#endif
}

inline __attribute__((always_inline)) VENOK_SOCKET_DESCRIPTOR bsd_bind_listen_fd(
        VENOK_SOCKET_DESCRIPTOR listenFd,
        struct addrinfo *listenAddr,
        int port,
        int options
) {

    if (port != 0) {
        /* Otherwise, always enable SO_REUSEPORT and SO_REUSEADDR _unless_ options specify otherwise */
#ifdef _WIN32
        if (options & VENOK_LISTEN_EXCLUSIVE_PORT) {
            int optval2 = 1;
            setsockopt(listenFd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (void *) &optval2, sizeof(optval2));
        } else {
            int optval3 = 1;
            setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval3, sizeof(optval3));
        }
#else
#if /*defined(__linux) &&*/ defined(SO_REUSEPORT)
        if (!(options & VENOK_LISTEN_EXCLUSIVE_PORT)) {
            int optval = 1;
            setsockopt(listenFd, SOL_SOCKET, SO_REUSEPORT, (void *) &optval, sizeof(optval));
        }
#endif
        int enabled = 1;
        setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (void *) &enabled, sizeof(enabled));
#endif
    }

#ifdef IPV6_V6ONLY
    int disabled = 0;
    setsockopt(listenFd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &disabled, sizeof(disabled));
#endif

    if (bind(listenFd, listenAddr->ai_addr, (socklen_t) listenAddr->ai_addrlen) || listen(listenFd, 512)) {
        return VENOK_SOCKET_ERROR;
    }

    return listenFd;
}

