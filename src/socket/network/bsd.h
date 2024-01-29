#ifndef VENOK_BSD_H
#define VENOK_BSD_H

#include "../structures.h"
#include "v_socket.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#define SETSOCKOPT_PTR_TYPE const char *
#define VENOK_SOCKET_ERROR INVALID_SOCKET
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* For socklen_t */
#include <sys/socket.h>
#define SETSOCKOPT_PTR_TYPE int *
#define VENOK_SOCKET_ERROR -1
#endif

#define VENOK_UDP_MAX_SIZE (64 * 1024)
#define VENOK_UDP_MAX_NUM 1024

struct bsd_addr {
    struct sockaddr_storage mem;
    socklen_t len;
    char *ip;
    int ip_length;
    int port;
};

/* TCP Layer*/
VENOK_SOCKET_DESCRIPTOR apple_no_sigpipe(VENOK_SOCKET_DESCRIPTOR fd);

VENOK_SOCKET_DESCRIPTOR bsd_set_nonblocking(VENOK_SOCKET_DESCRIPTOR fd);

void bsd_socket_nodelay(VENOK_SOCKET_DESCRIPTOR fd, int enabled);

void bsd_socket_flush(VENOK_SOCKET_DESCRIPTOR fd);

VENOK_SOCKET_DESCRIPTOR bsd_create_socket(int domain, int type, int protocol);

void bsd_close_socket(VENOK_SOCKET_DESCRIPTOR fd);

void bsd_shutdown_socket(VENOK_SOCKET_DESCRIPTOR fd);

void bsd_shutdown_socket_read(VENOK_SOCKET_DESCRIPTOR fd);

// called by dispatch_ready_poll
VENOK_SOCKET_DESCRIPTOR bsd_accept_socket(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr);

int bsd_recv(VENOK_SOCKET_DESCRIPTOR fd, void *buf, int length, int flags);

int bsd_send(VENOK_SOCKET_DESCRIPTOR fd, const char *buf, int length, int msg_more);

int bsd_write2(VENOK_SOCKET_DESCRIPTOR fd, const char *header, int header_length, const char *payload, int payload_length);

int bsd_would_block();

// return VENOK_SOCKET_ERROR or the fd that represents listen socket
// listen both on ipv6 and ipv4
VENOK_SOCKET_DESCRIPTOR bsd_create_listen_socket(const char *host, int port, int options);

VENOK_SOCKET_DESCRIPTOR bsd_create_listen_socket_unix(const char *path, int options);

/* Creates a UDP socket bound to the hostname and port */
VENOK_SOCKET_DESCRIPTOR bsd_create_udp_socket(const char *host, int port);

VENOK_SOCKET_DESCRIPTOR bsd_create_connect_socket(const char *host, int port, const char *source_host, int options);

VENOK_SOCKET_DESCRIPTOR bsd_create_connect_socket_unix(const char *server_path, int options);

/* UDP Layer */
int bsd_sendmmsg(VENOK_SOCKET_DESCRIPTOR fd, void *msgvec, unsigned int vlen, int flags);

int bsd_recvmmsg(VENOK_SOCKET_DESCRIPTOR fd, void *msgvec, unsigned int vlen, int flags, void *timeout);

int bsd_udp_packet_buffer_payload_length(void *msgvec, int index);

char *bsd_udp_packet_buffer_payload(void *msgvec, int index);

char *bsd_udp_packet_buffer_peer(void *msgvec, int index);

int bsd_udp_packet_buffer_local_ip(void *msgvec, int index, char *ip);

void *bsd_create_udp_packet_buffer();

void bsd_udp_buffer_set_packet_payload(struct v_udp_packet_buffer *send_buf, int index, int offset, void *payload, int length,
                                       void *peer_addr);

/* Shared Layer */

void internal_finalize_bsd_addr(struct bsd_addr *addr);

int bsd_local_addr(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr);

int bsd_remote_addr(VENOK_SOCKET_DESCRIPTOR fd, struct bsd_addr *addr);

char *bsd_addr_get_ip(struct bsd_addr *addr);

int bsd_addr_get_ip_length(struct bsd_addr *addr);

int bsd_addr_get_port(struct bsd_addr *addr);

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

#endif //VENOK_BSD_H
