#ifdef VENOK_USE_QUIC

#ifndef NETWORK_QUIC_H
#define NETWORK_QUIC_H

/* Experimental QUIC functions */
#include "lsquic.h"
#include "lsquic_types.h"
#include "lsxpack_header.h"

struct v_quic_socket_context_options {
    const char *cert_file_name;
    const char *key_file_name;
    const char *passphrase;
    const char **key;
    unsigned int key_count;
    const char **cert;
    unsigned int cert_count;
    const char **ca;
    unsigned int ca_count;

};

struct v_quic_socket {
    /* Refers to either the shared listen socket or the client UDP socket */
    void *udp_socket;
};

struct v_quic_socket_context;
struct v_quic_listen_socket;
struct v_quic_stream;

void *us_quic_stream_ext(struct v_quic_stream *s);

int us_quic_stream_write(struct v_quic_stream *s, char *data, int length);

int us_quic_stream_shutdown(struct v_quic_stream *s);

int us_quic_stream_shutdown_read(struct v_quic_stream *s);

void us_quic_stream_close(struct v_quic_stream *s);

int us_quic_socket_context_get_header(struct v_quic_socket_context *context, int index, char **name, int *name_length,
                                      char **value, int *value_length);


void us_quic_socket_context_set_header(struct v_quic_socket_context *context, int index, const char *key, int key_length,
                                       const char *value, int value_length);

void us_quic_socket_context_send_headers(struct v_quic_socket_context *context, struct v_quic_stream *s, int num,
                                         int has_body);

struct v_quic_socket_context *us_create_quic_socket_context(struct us_loop_t *loop, struct v_quic_socket_context_options options,
                                                            int ext_size);

struct v_quic_listen_socket *us_quic_socket_context_listen(struct v_quic_socket_context *context, const char *host, int port, int ext_size);

struct v_quic_socket *us_quic_socket_context_connect(struct v_quic_socket_context *context, const char *host, int port, int ext_size);

void us_quic_socket_create_stream(struct v_quic_socket *s, int ext_size);

struct v_quic_socket *us_quic_stream_socket(struct v_quic_stream *s);

/* This one is ugly and is only used to make clean examples */
int us_quic_stream_is_client(struct v_quic_stream *s);

void us_quic_socket_context_on_stream_data(struct v_quic_socket_context *context,
                                           void(*on_stream_data)(struct v_quic_stream *s, char *data, int length));

void us_quic_socket_context_on_stream_end(struct v_quic_socket_context *context,
                                          void(*on_stream_data)(struct v_quic_stream *s));

void us_quic_socket_context_on_stream_headers(struct v_quic_socket_context *context,
                                              void(*on_stream_headers)(struct v_quic_stream *s));

void us_quic_socket_context_on_stream_open(struct v_quic_socket_context *context,
                                           void(*on_stream_open)(struct v_quic_stream *s, int is_client));

void us_quic_socket_context_on_stream_close(struct v_quic_socket_context *context,
                                            void(*on_stream_close)(struct v_quic_stream *s));

void us_quic_socket_context_on_open(struct v_quic_socket_context *context,
                                    void(*on_open)(struct v_quic_socket *s, int is_client));

void us_quic_socket_context_on_close(struct v_quic_socket_context *context, void(*on_close)(struct v_quic_socket *s));

void us_quic_socket_context_on_stream_writable(struct v_quic_socket_context *context,
                                               void(*on_stream_writable)(struct v_quic_stream *s));

void *us_quic_socket_context_ext(struct v_quic_socket_context *context);

struct v_quic_socket_context *us_quic_socket_context(struct v_quic_socket *s);

#endif //NETWORK_QUIC_H
#endif
