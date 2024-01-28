#ifndef NETWORK_LOOP_H
#define NETWORK_LOOP_H

#include "structures.h"

/* Public interfaces for loops */

/* Returns a new event loop with user data extension */
struct v_loop *v_create_loop(void *hint, void (*wakeup_cb)(struct v_loop *loop),
                             void (*pre_cb)(struct v_loop *loop), void (*post_cb)(struct v_loop *loop),
                             unsigned int ext_size);

/* Frees the loop immediately */
void v_loop_free(struct v_loop *loop);

/* Returns the loop user data extension */
void *v_loop_ext(struct v_loop *loop);

/* Blocks the calling thread and drives the event loop until no more non-fallthrough polls are scheduled */
void v_loop_run(struct v_loop *loop);

/* Signals the loop from any thread to wake up and execute its wakeup handler from the loop's own running thread.
 * This is the only fully thread-safe function and serves as the basis for thread safety */
void v_wakeup_loop(struct v_loop *loop);

/* Hook up timers in existing loop */
void v_loop_integrate(struct v_loop *loop);

/* Returns the loop iteration number */
long long v_loop_iteration_number(struct v_loop *loop);

#endif //NETWORK_LOOP_H
