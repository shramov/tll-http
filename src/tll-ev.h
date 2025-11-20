// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#ifndef _TLL_EV_H
#define _TLL_EV_H

/*
 * libev emulation using TLL objects
 *
 * Limited to timer and io objects. IO object should have stable fd
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef double tll_ev_tstamp;
enum {
	EV_NONE = 0x00,
	EV_READ = 0x01,
	EV_WRITE = 0x02,
};

#define EV_DEFAULT NULL

struct tll_channel_t;
struct tll_channel_internal_t;
struct tll_ev_loop;

struct tll_ev_io;
struct tll_ev_timer;
typedef void (*tll_ev_io_cb_t)(struct tll_ev_loop *, struct tll_ev_io *, int);
typedef void (*tll_ev_timer_cb_t)(struct tll_ev_loop *, struct tll_ev_timer *, int);

typedef struct tll_ev_io
{
	struct tll_channel_t * self;
	tll_ev_io_cb_t cb;
	int fd;
	int events;
} tll_ev_io;

typedef struct tll_ev_timer
{
	struct tll_channel_t * self;
	tll_ev_timer_cb_t cb;
	tll_ev_tstamp at;
	tll_ev_tstamp repeat;
} tll_ev_timer;

void tll_ev_now_update(struct tll_ev_loop * loop);
tll_ev_tstamp tll_ev_now(struct tll_ev_loop * loop);

struct tll_ev_loop * tll_ev_loop_new(struct tll_channel_internal_t *);
void tll_ev_loop_destroy(struct tll_ev_loop *);

void tll_ev_timer_init(tll_ev_timer *ev, tll_ev_timer_cb_t cb, double at, double repeat);
void tll_ev_timer_start(struct tll_ev_loop *, tll_ev_timer *);
void tll_ev_timer_stop(struct tll_ev_loop *, tll_ev_timer *);

void tll_ev_io_init(tll_ev_io *ev, tll_ev_io_cb_t cb, int fd, int events);
void tll_ev_io_start(struct tll_ev_loop *, tll_ev_io *);
void tll_ev_io_stop(struct tll_ev_loop *, tll_ev_io *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif//_TLL_EV_H
