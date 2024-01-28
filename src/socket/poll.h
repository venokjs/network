#ifndef NETWORK_POLL_H
#define NETWORK_POLL_H

#include "structures.h"

/* Public interfaces for polls */

/* A fallthrough poll does not keep the loop running, it falls through */
struct v_poll *v_create_poll(struct v_loop *loop, int fallthrough, unsigned int ext_size);

/* After stopping a poll you must manually free the memory */
void v_poll_free(struct v_poll *p, struct v_loop *loop);

/* Associate this poll with a socket descriptor and poll type */
void v_poll_init(struct v_poll *p, VENOK_SOCKET_DESCRIPTOR fd, int poll_type);

/* Start, change and stop polling for events */
void v_poll_start(struct v_poll *p, struct v_loop *loop, int events);

void v_poll_change(struct v_poll *p, struct v_loop *loop, int events);

void v_poll_stop(struct v_poll *p, struct v_loop *loop);

/* Return what events we are polling for */
int v_poll_events(struct v_poll *p);

/* Returns the user data extension of this poll */
void *v_poll_ext(struct v_poll *p);

/* Get associated socket descriptor from a poll */
VENOK_SOCKET_DESCRIPTOR v_poll_fd(struct v_poll *p);

/* Resize an active poll */
struct v_poll *v_poll_resize(struct v_poll *p, struct v_loop *loop, unsigned int ext_size);

#endif //NETWORK_POLL_H
