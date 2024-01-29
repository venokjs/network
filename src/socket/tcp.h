#ifndef NETWORK_TCP_H
#define NETWORK_TCP_H

#include "structures.h"

struct v_socket_context_options {
    const char *key_file_name;
    const char *cert_file_name;
    const char *passphrase;
    const char *dh_params_file_name;
    const char *ca_file_name;
    const char *ssl_ciphers;
    int ssl_prefer_low_memory_usage; /* Todo: rename to prefer_low_memory_usage and apply for TCP as well */
    const char **key;
    unsigned int key_count;
    const char **cert;
    unsigned int cert_count;
    const char **ca;
    unsigned int ca_count;
    unsigned int secure_options;
    int reject_unauthorized;
    int request_cert;
};

/* Return 15-bit timestamp for this context */
unsigned short v_socket_context_timestamp(int ssl, struct v_socket_context *context);

/* Adds SNI domain and cert in asn1 format */
void v_socket_context_add_server_name(int ssl, struct v_socket_context *context, const char *hostname_pattern,
                                      struct v_bun_socket_context_options options, void *user);

void v_socket_context_remove_server_name(int ssl, struct v_socket_context *context, const char *hostname_pattern);

void v_socket_context_on_server_name(int ssl, struct v_socket_context *context,
                                     void (*cb)(struct v_socket_context *, const char *hostname));

void *v_socket_server_name_userdata(int ssl, struct v_socket *s);

void *v_socket_context_find_server_name_userdata(int ssl, struct v_socket_context *context, const char *hostname_pattern);

/* Returns the underlying SSL native handle, such as SSL_CTX or nullptr */
void *v_socket_context_get_native_handle(int ssl, struct v_socket_context *context);

/* A socket context holds shared callbacks and user data extension for associated sockets */
struct v_socket_context *v_create_socket_context(int ssl, struct v_loop *loop,
                                                 int ext_size, struct v_bun_socket_context_options options);

/* Delete resources allocated at creation time. */
void v_socket_context_free(int ssl, struct v_socket_context *context);

struct v_socket_context_options v_socket_verify_error(int ssl, struct v_socket *context);

/* Setters of various async callbacks */
void v_socket_context_on_pre_open(int ssl, struct v_socket_context *context,
                                  VENOK_SOCKET_DESCRIPTOR (*on_pre_open)(VENOK_SOCKET_DESCRIPTOR fd));

void v_socket_context_on_open(int ssl, struct v_socket_context *context,
                              struct v_socket *(*on_open)(struct v_socket *s, int is_client, char *ip,
                                                          int ip_length));

void v_socket_context_on_close(int ssl, struct v_socket_context *context,
                               struct v_socket *(*on_close)(struct v_socket *s, int code, void *reason));

void v_socket_context_on_data(int ssl, struct v_socket_context *context,
                              struct v_socket *(*on_data)(struct v_socket *s, char *data, int length));

void v_socket_context_on_writable(int ssl, struct v_socket_context *context,
                                  struct v_socket *(*on_writable)(struct v_socket *s));

void v_socket_context_on_timeout(int ssl, struct v_socket_context *context,
                                 struct v_socket *(*on_timeout)(struct v_socket *s));

void v_socket_context_on_long_timeout(int ssl, struct v_socket_context *context,
                                      struct v_socket *(*on_timeout)(struct v_socket *s));

/* This one is only used for when a connecting socket fails in a late stage. */
void v_socket_context_on_connect_error(int ssl, struct v_socket_context *context,
                                       struct v_socket *(*on_connect_error)(struct v_socket *s, int code));

/* Emitted when a socket has been half-closed */
void v_socket_context_on_end(int ssl, struct v_socket_context *context,
                             struct v_socket *(*on_end)(struct v_socket *s));

/* Returns user data extension for this socket context */
void *v_socket_context_ext(int ssl, struct v_socket_context *context);

/* Closes all open sockets, including listen sockets. Does not invalidate the socket context. */
void v_socket_context_close(int ssl, struct v_socket_context *context);

/* Listen for connections. Acts as the main driving cog in a server. Will call set async callbacks. */
struct v_listen_socket *v_socket_context_listen(int ssl, struct v_socket_context *context,
                                                const char *host, int port, int options, int socket_ext_size);

struct v_listen_socket *v_socket_context_listen_unix(int ssl, struct v_socket_context *context,
                                                     const char *path, int options, int socket_ext_size);

/* listen_socket.c/.h */
void v_listen_socket_close(int ssl, struct v_listen_socket *ls);

/* Adopt a socket which was accepted either internally, or from another accept() outside v_sockets */
struct v_socket *v_adopt_accepted_socket(int ssl, struct v_socket_context *context, VENOK_SOCKET_DESCRIPTOR client_fd,
                                         unsigned int socket_ext_size, char *addr_ip, int addr_ip_length);

/* Land in on_open or on_connection_error or return null or return socket */
struct v_socket *v_socket_context_connect(int ssl, struct v_socket_context *context,
                                          const char *host, int port, const char *source_host, int options,
                                          int socket_ext_size);

struct v_socket *v_socket_context_connect_unix(int ssl, struct v_socket_context *context,
                                               const char *server_path, int options, int socket_ext_size);

/* Is this socket established? Can be used to check if a connecting socket has fired the on_open event yet.
 * Can also be used to determine if a socket is a listen_socket or not, but you probably know that already. */
int v_socket_is_established(int ssl, struct v_socket *s);

/* Cancel a connecting socket. Can be used together with v_socket_timeout to limit connection times.
 * Entirely destroys the socket - this function works like v_socket_close but does not trigger on_close event since
 * you never got the on_open event first. */
struct v_socket *v_socket_close_connecting(int ssl, struct v_socket *s);

/* Returns the loop for this socket context. */
struct v_loop *v_socket_context_loop(int ssl, struct v_socket_context *context);

/* Invalidates passed socket, returning a new resized socket which belongs to a different socket context.
 * Used mainly for "socket upgrades" such as when transitioning from HTTP to WebSocket. */
struct v_socket *
v_socket_context_adopt_socket(int ssl, struct v_socket_context *context, struct v_socket *s, int ext_size);

/* Create a child socket context which acts much like its own socket context with its own callbacks yet still relies on the
 * parent socket context for some shared resources. Child socket contexts should be used together with socket adoptions and nothing else. */
struct v_socket_context *v_create_child_socket_context(int ssl, struct v_socket_context *context, int context_ext_size);

#endif //NETWORK_TCP_H
