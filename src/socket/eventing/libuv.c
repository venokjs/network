#include <stdlib.h>
#include "v_socket.h"
#include "../internal/internal.h"

#ifdef VENOK_USE_LIBUV

/* uv_poll_t->data always (except for most times after calling v_poll_stop) points to the v_poll */
static void poll_cb(uv_poll_t *p, int status, int events) {
    v_internal_dispatch_ready_poll((struct v_poll *) p->data, status < 0, events);
}

static void prepare_cb(uv_prepare_t *p) {
    struct v_loop *loop = p->data;
    v_internal_loop_pre(loop);
}

/* Note: libuv timers execute AFTER the post callback */
static void check_cb(uv_check_t *p) {
    struct v_loop *loop = p->data;
    v_internal_loop_post(loop);
}

/* Not used for polls, since polls need two frees */
static void close_cb_free(uv_handle_t *h) {
    free(h->data);
}

static void close_cb_free_poll(uv_handle_t *h) {
    /* It is only in case we called v_poll_stop then quickly v_poll_free that we enter this.
     * Most of the time, actual freeing is done by v_poll_free. */
    if (h->data) {
        free(h->data);
        free(h);
    }
}

static void timer_cb(uv_timer_t *t) {
    struct v_internal_callback *cb = t->data;
    cb->cb(cb);
}

static void async_cb(uv_async_t *a) {
    struct v_internal_callback *cb = a->data;
    // internal asyncs give their loop, not themselves
    cb->cb((struct v_internal_callback *) cb->loop);
}

/* Poll*/
void v_poll_init(struct v_poll *p, VENOK_SOCKET_DESCRIPTOR fd, int poll_type) {
    p->poll_type = poll_type;
    p->fd = fd;
}

void v_poll_free(struct v_poll *p, struct v_loop *loop) {
    /* The idea here is like so; in v_poll_stop we call uv_close after setting data of uv-poll to 0.
     * This means that in close_cb_free we call free on 0 with does nothing, since v_poll_stop should
     * not really free the poll. HOWEVER, if we then call v_poll_free while still closing the uv-poll,
     * we simply change back the data to point to our structure so that we actually do free it like we should. */
    if (uv_is_closing((uv_handle_t *) p->uv_p))p->uv_p->data = p;
    else {
        free(p->uv_p);
        free(p);
    }
}

void v_poll_start(struct v_poll *p, struct v_loop *loop, int events) {
    p->poll_type = v_internal_poll_type(p) | ((events & VENOK_SOCKET_READABLE) ? POLL_TYPE_POLLING_IN : 0) |
                   ((events & VENOK_SOCKET_WRITABLE) ? POLL_TYPE_POLLING_OUT : 0);

    uv_poll_init_socket(loop->uv_loop, p->uv_p, p->fd);
    uv_poll_start(p->uv_p, events, poll_cb);
}

void v_poll_change(struct v_poll *p, struct v_loop *loop, int events) {
    if (v_poll_events(p) != events) {
        p->poll_type = v_internal_poll_type(p) | ((events & VENOK_SOCKET_READABLE) ? POLL_TYPE_POLLING_IN : 0) |
                       ((events & VENOK_SOCKET_WRITABLE) ? POLL_TYPE_POLLING_OUT : 0);

        uv_poll_start(p->uv_p, events, poll_cb);
    }
}

void v_poll_stop(struct v_poll *p, struct v_loop *loop) {
    uv_poll_stop(p->uv_p);

    /* We normally only want to close the poll here, not free it. But if we stop it, then quickly "free" it with
     * v_poll_free, we postpone the actual freeing to close_cb_free_poll whenever it triggers.
     * That's why we set data to null here, so that v_poll_free can reset it if needed */
    p->uv_p->data = 0;
    uv_close((uv_handle_t *) p->uv_p, close_cb_free_poll);
}

int v_poll_events(struct v_poll *p) {
    return ((p->poll_type & POLL_TYPE_POLLING_IN) ? VENOK_SOCKET_READABLE : 0) |
           ((p->poll_type & POLL_TYPE_POLLING_OUT) ? VENOK_SOCKET_WRITABLE : 0);
}

unsigned int v_internal_accept_poll_event(struct v_poll *p) {
    return 0;
}

int v_internal_poll_type(struct v_poll *p) {
    return p->poll_type & 3;
}

void v_internal_poll_set_type(struct v_poll *p, int poll_type) {
    p->poll_type = poll_type | (p->poll_type & 12);
}

VENOK_SOCKET_DESCRIPTOR v_poll_fd(struct v_poll *p) {
    return p->fd;
}

void v_loop_pump(struct v_loop *loop) {
    uv_run(loop->uv_loop, UV_RUN_NOWAIT);
}

struct v_loop *v_create_loop(void *hint, void (*wakeup_cb)(struct v_loop *loop),
                             void (*pre_cb)(struct v_loop *loop), void (*post_cb)(struct v_loop *loop),
                             unsigned int ext_size) {
    struct v_loop *loop = (struct v_loop *) malloc(sizeof(struct v_loop) + ext_size);

    loop->uv_loop = hint ? hint : uv_loop_new();
    loop->is_default = hint != 0;

    loop->uv_pre = malloc(sizeof(uv_prepare_t));
    uv_prepare_init(loop->uv_loop, loop->uv_pre);
    uv_prepare_start(loop->uv_pre, prepare_cb);
    uv_unref((uv_handle_t *) loop->uv_pre);
    loop->uv_pre->data = loop;

    loop->uv_check = malloc(sizeof(uv_check_t));
    uv_check_init(loop->uv_loop, loop->uv_check);
    uv_unref((uv_handle_t *) loop->uv_check);
    uv_check_start(loop->uv_check, check_cb);
    loop->uv_check->data = loop;

    // here we create two unrefereed handles - timer and async
    v_internal_loop_data_init(loop, wakeup_cb, pre_cb, post_cb);

    // if we do not own this loop, we need to integrate and set up timer
    if (hint) v_loop_integrate(loop);

    return loop;
}

// based on if this was default loop or not
void v_loop_free(struct v_loop *loop) {
    // ref and close down prepare and check
    uv_ref((uv_handle_t *) loop->uv_pre);
    uv_prepare_stop(loop->uv_pre);
    loop->uv_pre->data = loop->uv_pre;
    uv_close((uv_handle_t *) loop->uv_pre, close_cb_free);

    uv_ref((uv_handle_t *) loop->uv_check);
    uv_check_stop(loop->uv_check);
    loop->uv_check->data = loop->uv_check;
    uv_close((uv_handle_t *) loop->uv_check, close_cb_free);

    v_internal_loop_data_free(loop);

    // we need to run the loop one last round to call all close callbacks
    // we cannot do this if we do not own the loop, default
    if (!loop->is_default) {
        uv_run(loop->uv_loop, UV_RUN_NOWAIT);
        uv_loop_delete(loop->uv_loop);
    }

    // now we can free our part
    free(loop);
}

void v_loop_run(struct v_loop *loop) {
    v_loop_integrate(loop);

    uv_run(loop->uv_loop, UV_RUN_DEFAULT);
}

struct v_poll *v_create_poll(struct v_loop *loop, int fallthrough, unsigned int ext_size) {
    struct v_poll *p = (struct v_poll *) malloc(sizeof(struct v_poll) + ext_size);
    p->uv_p = malloc(sizeof(uv_poll_t));
    p->uv_p->data = p;
    return p;
}

/* If we update our block position we have to update the uv_poll data to point to us */
struct v_poll *v_poll_resize(struct v_poll *p, struct v_loop *loop, unsigned int ext_size) {
    struct v_poll *new_p = realloc(p, sizeof(struct v_poll) + ext_size);
    new_p->uv_p->data = new_p;
    return new_p;
}

/* Timer*/
struct v_timer *v_create_timer(struct v_loop *loop, int fallthrough, unsigned int ext_size) {
    struct v_internal_callback *cb = malloc(sizeof(struct v_internal_callback) + sizeof(uv_timer_t) + ext_size);

    cb->loop = loop;
    cb->cb_expects_the_loop = 0; // never read?
    cb->leave_poll_ready = 0; // never read?

    uv_timer_t *uv_timer = (uv_timer_t *) (cb + 1);
    uv_timer_init(loop->uv_loop, uv_timer);
    uv_timer->data = cb;

    if (fallthrough) uv_unref((uv_handle_t *) uv_timer);

    return (struct v_timer *) cb;
}

void *v_timer_ext(struct v_timer *timer) {
    return ((char *) timer) + sizeof(struct v_internal_callback) + sizeof(uv_timer_t);
}

void v_timer_close(struct v_timer *t) {
    struct v_internal_callback *cb = (struct v_internal_callback *) t;

    uv_timer_t *uv_timer = (uv_timer_t *) (cb + 1);

    // always ref the timer before closing it
    uv_ref((uv_handle_t *) uv_timer);

    uv_timer_stop(uv_timer);

    uv_timer->data = cb;
    uv_close((uv_handle_t *) uv_timer, close_cb_free);
}

void v_timer_set(struct v_timer *t, void (*cb)(struct v_timer *t), int ms, int repeat_ms) {
    struct v_internal_callback *internal_cb = (struct v_internal_callback *) t;

    internal_cb->cb = (void (*)(struct v_internal_callback *)) cb;

    uv_timer_t *uv_timer = (uv_timer_t *) (internal_cb + 1);
    if (!ms) uv_timer_stop(uv_timer);
    else uv_timer_start(uv_timer, timer_cb, ms, repeat_ms);
}

struct v_loop *v_timer_loop(struct v_timer *t) {
    struct v_internal_callback *internal_cb = (struct v_internal_callback *) t;
    return internal_cb->loop;
}

// async (internal only)
struct v_internal_async *v_internal_create_async(struct v_loop *loop, int fallthrough, unsigned int ext_size) {
    struct v_internal_callback *cb = malloc(sizeof(struct v_internal_callback) + sizeof(uv_async_t) + ext_size);

    cb->loop = loop;
    return (struct v_internal_async *) cb;
}

void v_internal_async_close(struct v_internal_async *a) {
    struct v_internal_callback *cb = (struct v_internal_callback *) a;

    uv_async_t *uv_async = (uv_async_t *) (cb + 1);

    // always ref the async before closing it
    uv_ref((uv_handle_t *) uv_async);

    uv_async->data = cb;
    uv_close((uv_handle_t *) uv_async, close_cb_free);
}

void v_internal_async_set(struct v_internal_async *a, void (*cb)(struct v_internal_async *)) {
    struct v_internal_callback *internal_cb = (struct v_internal_callback *) a;

    internal_cb->cb = (void (*)(struct v_internal_callback *)) cb;

    uv_async_t *uv_async = (uv_async_t *) (internal_cb + 1);
    uv_async_init(internal_cb->loop->uv_loop, uv_async, async_cb);
    uv_unref((uv_handle_t *) uv_async);
    uv_async->data = internal_cb;
}

void v_internal_async_wakeup(struct v_internal_async *a) {
    struct v_internal_callback *internal_cb = (struct v_internal_callback *) a;

    uv_async_t *uv_async = (uv_async_t *) (internal_cb + 1);
    uv_async_send(uv_async);
}

#endif
