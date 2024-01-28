#ifndef NETWORK_STRUCTURES_H
#define NETWORK_STRUCTURES_H

#ifdef _WIN32

#include <winsock2.h>

#define VENOK_SOCKET_DESCRIPTOR SOCKET
#else
#define VENOK_SOCKET_DESCRIPTOR int
#endif

struct v_socket;
struct v_socket_context;
struct v_loop;
struct v_poll;
struct v_timer;
struct v_udp_socket;
struct v_udp_packet_buffer;

#endif //NETWORK_STRUCTURES_H
