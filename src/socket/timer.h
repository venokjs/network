#ifndef NETWORK_TIMER_H
#define NETWORK_TIMER_H

#include "structures.h"

/* Public interfaces for timers */

/* Create a new high precision, low performance timer. May fail and return null */
struct v_timer *v_create_timer(struct v_loop *loop, int fallthrough, unsigned int ext_size);

/* Returns user data extension for this timer */
void *v_timer_ext(struct v_timer *timer);

/* Close timer */
void v_timer_close(struct v_timer *timer);

/* Arm a timer with a delay from now and eventually a repeat delay.
 * Specify 0 as repeat delay to disable repeating. Specify both 0 to disarm. */
void v_timer_set(struct v_timer *timer, void (*cb)(struct v_timer *t), int ms, int repeat_ms);

/* Returns the loop for this timer */
struct v_loop *v_timer_loop(struct v_timer *t);

#endif //NETWORK_TIMER_H
