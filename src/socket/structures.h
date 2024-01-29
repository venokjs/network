#ifndef NETWORK_STRUCTURES_H
#define NETWORK_STRUCTURES_H

#ifdef _WIN32

#include <winsock2.h>

/* Define what a socket descriptor is based on platform */
#define VENOK_SOCKET_DESCRIPTOR SOCKET
#else
#define VENOK_SOCKET_DESCRIPTOR int
#endif

/* 512kb shared receive buffer */
#define VENOK_RECV_BUFFER_LENGTH 524288
/* A timeout granularity of 4 seconds means give or take 4 seconds from set timeout */
#define VENOK_TIMEOUT_GRANULARITY 4
/* 32 byte padding of receive buffer ends */
#define VENOK_RECV_BUFFER_PADDING 32
/* Guaranteed alignment of extension memory */
#define VENOK_EXT_ALIGNMENT 16

/* Decide what eventing system to use by default */
#if !defined(VENOK_USE_EPOLL) && !defined(VENOK_USE_LIBUV) && !defined(VENOK_USE_KQUEUE)
#if defined(_WIN32)
#define VENOK_USE_LIBUV
#elif defined(__APPLE__) || defined(__FreeBSD__)
#define VENOK_USE_KQUEUE
#else
#define VENOK_USE_EPOLL
#endif
#endif

struct v_socket;
struct v_socket_context;
struct v_loop;
struct v_poll;
struct v_timer;
struct v_udp_socket;
struct v_udp_packet_buffer;

#endif //NETWORK_STRUCTURES_H
