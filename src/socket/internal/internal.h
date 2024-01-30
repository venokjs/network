#ifndef VENOK_INTERNAL_H
#define VENOK_INTERNAL_H

#if defined(_MSC_VER)
#ifndef __cplusplus
#define alignas(x) __declspec(align(x))
#endif
#else
#include <stdalign.h>
#endif

#if defined(VENOK_USE_KQUEUE)
#include <mach/mach.h>
#endif

#include "../network/bsd.h"

/* We have many different eventing implementations */
#if defined(VENOK_USE_EPOLL) || defined(VENOK_USE_KQUEUE)
#include "../eventing/epoll_kqueue.h"
#endif

#ifdef VENOK_USE_LIBUV
#include "../eventing/libuv.h"
#endif

struct v_cert_string {
    const char *str;
    size_t len;
};

/* Poll type and what it polls for */
enum {
    /* Two first bits */
    POLL_TYPE_SOCKET = 0,
    POLL_TYPE_SOCKET_SHUT_DOWN = 1,
    POLL_TYPE_SEMI_SOCKET = 2,
    POLL_TYPE_CALLBACK = 3,

    /* Two last bits */
    POLL_TYPE_POLLING_OUT = 4,
    POLL_TYPE_POLLING_IN = 8
};

#if defined(VENOK_USE_EPOLL) || defined(VENOK_USE_KQUEUE)
#define VENOK_MAX_READY_POLLS 1024
void v_internal_loop_update_pending_ready_polls(struct v_loop *loop, struct v_poll *old_poll, struct v_poll *new_poll, int old_events,
                                                int new_events);
#endif

/* Loop related */
void v_internal_dispatch_ready_poll(struct v_poll *p, int error, int events);
void v_internal_timer_sweep(struct v_loop *loop);
void v_internal_free_closed_sockets(struct v_loop *loop);
void v_internal_loop_link(struct v_loop *loop, struct v_socket_context *context);
void v_internal_loop_unlink(struct v_loop *loop, struct v_socket_context *context);
void v_internal_loop_data_init(struct v_loop *loop, void (*wakeup_cb)(struct v_loop *loop),
                               void (*pre_cb)(struct v_loop *loop), void (*post_cb)(struct v_loop *loop));
void v_internal_loop_data_free(struct v_loop *loop);
void v_internal_loop_pre(struct v_loop *loop);
void v_internal_loop_post(struct v_loop *loop);

/* Asyncs (old) */
struct v_internal_async *v_internal_create_async(struct v_loop *loop, int fallthrough, unsigned int ext_size);
void v_internal_async_close(struct v_internal_async *a);
void v_internal_async_set(struct v_internal_async *a, void (*cb)(struct v_internal_async *));
void v_internal_async_wakeup(struct v_internal_async *a);

/* Eventing related */
unsigned int v_internal_accept_poll_event(struct v_poll *p);
int v_internal_poll_type(struct v_poll *p);
void v_internal_poll_set_type(struct v_poll *p, int poll_type);

/* SSL loop data */
void v_internal_init_loop_ssl_data(struct v_loop *loop);
void v_internal_free_loop_ssl_data(struct v_loop *loop);

/* Socket context related */
void v_internal_socket_context_link_socket(struct v_socket_context *context, struct v_socket *s);
void v_internal_socket_context_unlink_socket(struct v_socket_context *context, struct v_socket *s);

/* Sockets are polls */
struct v_socket {
    alignas(VENOK_EXT_ALIGNMENT) struct v_poll p; // 4 bytes
    unsigned char timeout;                           // 1 byte
    unsigned char long_timeout;                      // 1 byte
    /*
     * 0 = not in low-prio queue
     * 1 = is in low-prio queue
     * 2 = was in low-prio queue in this iteration
     * */
    unsigned short low_prio_state;
    struct v_socket_context *context;
    struct v_socket *prev, *next;
};

struct v_internal_callback {
    alignas(VENOK_EXT_ALIGNMENT) struct v_poll p;
    struct v_loop *loop;
    int cb_expects_the_loop;
    int leave_poll_ready;
    void (*cb)(struct v_internal_callback *cb);
#if defined(VENOK_USE_KQUEUE)
    mach_port port;
    void *machport_buf;
#else
    unsigned has_added_timer_to_event_loop;
#endif
};

/* Listen sockets are sockets */
struct v_listen_socket {
    alignas(VENOK_EXT_ALIGNMENT) struct v_socket s;
    unsigned int socket_ext_size;
};

/* Listen sockets are keeps in their own list */
void v_internal_socket_context_link_listen_socket(struct v_socket_context *context, struct v_listen_socket *s);
void v_internal_socket_context_unlink_listen_socket(struct v_socket_context *context, struct v_listen_socket *s);

struct v_socket_context {
    alignas(VENOK_EXT_ALIGNMENT) struct v_loop *loop;
    long global_tick;
    unsigned char timestamp;
    unsigned char long_timestamp;
    struct v_socket *head_sockets;
    struct v_listen_socket *head_listen_sockets;
    struct v_socket *iterator;
    struct v_socket_context *prev, *next;

    VENOK_SOCKET_DESCRIPTOR (*on_pre_open)(VENOK_SOCKET_DESCRIPTOR fd);
    struct v_socket *(*on_open)(struct v_socket *, int is_client, char *ip, int ip_length);
    struct v_socket *(*on_data)(struct v_socket *, char *data, int length);
    struct v_socket *(*on_writable)(struct v_socket *);
    struct v_socket *(*on_close)(struct v_socket *, int code, void *reason);
    struct v_socket *(*on_socket_timeout)(struct v_socket *);
    struct v_socket *(*on_socket_long_timeout)(struct v_socket *);
    struct v_socket *(*on_end)(struct v_socket *);
    struct v_socket *(*on_connect_error)(struct v_socket *, int code);
    int (*is_low_prio)(struct v_socket *);
};

/* Internal SSL interface (all ssl are internal, because we don't use _internal_ in functions) */
#ifndef VENOK_NO_SSL

struct v_ssl_socket_context;
struct v_ssl_socket;

/* SNI functions */
void v_ssl_socket_context_add_server_name(struct v_ssl_socket_context *context, const char *hostname_pattern,
                                          struct v_socket_context_options options, void *user);
void v_ssl_socket_context_remove_server_name(struct v_ssl_socket_context *context, const char *hostname_pattern);
void v_ssl_socket_context_on_server_name(struct v_ssl_socket_context *context,
                                         void (*cb)(struct v_ssl_socket_context *, const char *));
void *v_ssl_socket_get_sni_userdata(struct v_ssl_socket *s);
void *v_ssl_socket_context_find_server_name_userdata(struct v_ssl_socket_context *context, const char *hostname_pattern);
void *v_ssl_socket_get_native_handle(struct v_ssl_socket *s);
void *v_ssl_socket_context_get_native_handle(struct v_ssl_socket_context *context);
struct v_ssl_socket_context *v_create_ssl_socket_context(struct v_loop *loop, int context_ext_size,
                                                         struct v_socket_context_options options);

void v_ssl_socket_context_free(struct v_ssl_socket_context *context);
void v_ssl_socket_context_on_open(struct v_ssl_socket_context *context,
                                  struct v_ssl_socket *(*on_open)(struct v_ssl_socket *s, int is_client, char *ip, int ip_length));
void v_ssl_socket_context_on_close(struct v_ssl_socket_context *context,
                                   struct v_ssl_socket *(*on_close)(struct v_ssl_socket *s, int code, void *reason));
void v_ssl_socket_context_on_data(struct v_ssl_socket_context *context,
                                  struct v_ssl_socket *(*on_data)(struct v_ssl_socket *s, char *data, int length));

void v_ssl_socket_context_on_writable(struct v_ssl_socket_context *context,
                                      struct v_ssl_socket *(*on_writable)(struct v_ssl_socket *s));

void v_ssl_socket_context_on_timeout(struct v_ssl_socket_context *context,
                                     struct v_ssl_socket *(*on_timeout)(struct v_ssl_socket *s));

void v_ssl_socket_context_on_long_timeout(struct v_ssl_socket_context *context,
                                          struct v_ssl_socket *(*on_timeout)(struct v_ssl_socket *s));
void v_ssl_socket_context_on_end(struct v_ssl_socket_context *context,
                                 struct v_ssl_socket *(*on_end)(struct v_ssl_socket *s));

void v_ssl_socket_context_on_connect_error(struct v_ssl_socket_context *context,
                                           struct v_ssl_socket *(*on_connect_error)(
                                                   struct v_ssl_socket *s, int code));

struct v_listen_socket *v_ssl_socket_context_listen(struct v_ssl_socket_context *context,
                                                    const char *host, int port, int options,
                                                    int socket_ext_size);

struct v_listen_socket *v_ssl_socket_context_listen_unix(struct v_ssl_socket_context *context,
                                                         const char *path, int options,
                                                         int socket_ext_size);

struct v_ssl_socket *v_ssl_adopt_accepted_socket(struct v_ssl_socket_context *context, VENOK_SOCKET_DESCRIPTOR accepted_fd,
                                                 unsigned int socket_ext_size, char *addr_ip, int addr_ip_length);

struct v_ssl_socket *v_ssl_socket_context_connect(struct v_ssl_socket_context *context,
                                                  const char *host, int port,
                                                  const char *source_host, int options, int socket_ext_size);

struct v_ssl_socket *v_ssl_socket_context_connect_unix(struct v_ssl_socket_context *context,
                                                       const char *server_path, int options,
                                                       int socket_ext_size);

int v_ssl_socket_write(struct v_ssl_socket *s, const char *data, int length, int msg_more);

void v_ssl_socket_timeout(struct v_ssl_socket *s, unsigned int seconds);
void *v_ssl_socket_context_ext(struct v_ssl_socket_context *s);
struct v_ssl_socket_context *v_ssl_socket_get_context(struct v_ssl_socket *s);
void *v_ssl_socket_ext(struct v_ssl_socket *s);
int v_ssl_socket_is_shutdown(struct v_ssl_socket *s);
void v_ssl_socket_shutdown(struct v_ssl_socket *s);

struct v_ssl_socket *v_ssl_socket_context_adopt_socket(struct v_ssl_socket_context *context, struct v_ssl_socket *s, int ext_size);
struct v_ssl_socket_context *v_create_child_ssl_socket_context(struct v_ssl_socket_context *context, int context_ext_size);
struct v_loop *v_ssl_socket_context_loop(struct v_ssl_socket_context *context);
struct v_ssl_socket *v_ssl_socket_open(struct v_ssl_socket *s, int is_client, char *ip, int ip_length);
#endif
#endif //VENOK_INTERNAL_H
