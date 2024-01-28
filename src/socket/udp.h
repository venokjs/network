#ifndef NETWORK_UDP_H
#define NETWORK_UDP_H

#include "structures.h"

/* Public interface for UDP sockets */

/* Peeks data of UDP payload */
char *v_udp_packet_buffer_payload(struct v_udp_packet_buffer *buf, int index);

/* Peeks length of UDP payload */
int v_udp_packet_buffer_payload_length(struct v_udp_packet_buffer *buf, int index);

/* Peeks peer addr (sockaddr) of received packet */
char *v_udp_packet_buffer_peer(struct v_udp_packet_buffer *buf, int index);

/* Peeks ECN of received packet */
int v_udp_packet_buffer_ecn(struct v_udp_packet_buffer *buf, int index);

/* Copies out local (received destination) ip (4 or 16 bytes) of received packet */
int v_udp_packet_buffer_local_ip(struct v_udp_packet_buffer *buf, int index, char *ip);

/* Get the bound port in host byte order */
int v_udp_socket_bound_port(struct v_udp_socket *s);

/* Receives a set of packets into specified packet buffer */
int v_udp_socket_receive(struct v_udp_socket *s, struct v_udp_packet_buffer *buf);

void v_udp_buffer_set_packet_payload(struct v_udp_packet_buffer *send_buf, int index, int offset, void *payload, int length,
                                     void *peer_addr);

int v_udp_socket_send(struct v_udp_socket *s, struct v_udp_packet_buffer *buf, int num);

/* Allocates a packet buffer that is reusable per thread. Mutated by v_udp_socket_receive. */
struct v_udp_packet_buffer *v_create_udp_packet_buffer();

/* Creates a (heavy-weight) UDP socket with a user space ring buffer. Again, this one is heavyweight and
 * should be reused. One entire QUIC server can be implemented using only one single UDP socket so weight
 * is not a concern as is the case for TCP sockets which are 1-to-1 with TCP connections. */
struct v_udp_socket *v_create_udp_socket(struct v_loop *loop, struct v_udp_packet_buffer *buf,
                                         void (*data_cb)(struct v_udp_socket *, struct v_udp_packet_buffer *, int),
                                         void (*drain_cb)(struct v_udp_socket *), const char *host, unsigned short port,
                                         void *user);

/* Returns user data extension for this socket */
void *v_udp_socket_ext(struct v_udp_socket *s);

/* Binds the UDP socket to an interface and port */
int v_udp_socket_bind(struct v_udp_socket *s, const char *hostname, unsigned int port);

#endif //NETWORK_UDP_H
