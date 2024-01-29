#ifndef VENOK_LOOP_DATA_H
#define VENOK_LOOP_DATA_H

struct v_internal_loop_data {
    struct v_timer *sweep_timer;
    struct v_internal_async *wakeup_async;
    int last_write_failed;
    struct v_socket_context *head;
    struct v_socket_context *iterator;
    char *recv_buf;
    void *ssl_data;
    void (*pre_cb)(struct v_loop *);
    void (*post_cb)(struct v_loop *);
    struct v_socket *closed_head;
    struct v_socket *low_prio_head;
    int low_prio_budget;
    /* We do not care if this flips or not, it doesn't matter */
    long long iteration_nr;
};

#endif //VENOK_LOOP_DATA_H
