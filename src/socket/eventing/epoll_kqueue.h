#ifndef VENOK_EPOLL_KQUEUE_H
#define VENOK_EPOLL_KQUEUE_H

#include "../structures.h"
#include "../internal/loop_data.h"

#ifdef VENOK_USE_EPOLL
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#define VENOK_SOCKET_READABLE EPOLLIN
#define VENOK_SOCKET_WRITABLE EPOLLOUT
#elif defined(VENOK_USE_KQUEUE)
#include <sys/event.h>
/* Kqueue EVFILT_ is NOT a bitfield, you cannot OR together them.
 * We therefore have our own bitfield we then translate in every call */
#define VENOK_SOCKET_READABLE 1
#define VENOK_SOCKET_WRITABLE 2

#include <mach/mach.h>
#endif

struct v_loop {
    alignas(VENOK_EXT_ALIGNMENT) struct v_internal_loop_data data;

    /* Number of non-fallthrough polls in the loop */
    int num_polls;

    /* Number of ready polls this iteration */
    int num_ready_polls;

    /* Current index in list of ready polls */
    int current_ready_poll;

    /* Loop's own file descriptor */
    int fd;

    /* The list of ready polls */
#ifdef VENOK_USE_EPOLL
    alignas(VENOK_EXT_ALIGNMENT) struct epoll_event ready_polls[1024];
#elif defined(VENOK_USE_KQUEUE)
    alignas(VENOK_EXT_ALIGNMENT) struct kevent64_s ready_polls[1024];
#endif
};

struct v_poll {
    alignas(VENOK_EXT_ALIGNMENT) struct {
        signed int fd: 28; // we could have this unsigned if we wanted to, -1 should never be used
        unsigned int poll_type: 4;
    } state;
};

#endif //VENOK_EPOLL_KQUEUE_H
