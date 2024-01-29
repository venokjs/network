#ifndef VENOK_LIBUV_H
#define VENOK_LIBUV_H

#include "../structures.h"
#include "../internal/loop_data.h"

#include <uv.h>
#define VENOK_SOCKET_READABLE UV_READABLE
#define VENOK_SOCKET_WRITABLE UV_WRITABLE

struct v_loop {
    alignas(VENOK_EXT_ALIGNMENT) struct v_internal_loop_data data;

    uv_loop_t *uv_loop;
    int is_default;

    uv_prepare_t *uv_pre;
    uv_check_t *uv_check;
};

struct v_poll {
    /* We need to hold a pointer to this uv_poll_t since we need to be able to
     * resize our block */
    uv_poll_t *uv_p;
    VENOK_SOCKET_DESCRIPTOR fd;
    unsigned char poll_type;
};

#endif //VENOK_LIBUV_H
