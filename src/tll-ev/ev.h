// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#ifndef _EV_WRAP_H
#define _EV_WRAP_H

// Use TLL libev emulation shim

#include <tll-ev.h>

#define ev_tstamp tll_ev_tstamp
#define ev_now tll_ev_now

#define ev_loop tll_ev_loop
#define ev_loop_new tll_ev_loop_new
#define ev_loop_destroy tll_ev_loop_destroy

#define ev_timer tll_ev_timer
#define ev_timer_init tll_ev_timer_init
#define ev_timer_start tll_ev_timer_start
#define ev_timer_stop tll_ev_timer_stop

#define ev_io tll_ev_io
#define ev_io_init tll_ev_io_init
#define ev_io_start tll_ev_io_start
#define ev_io_stop tll_ev_io_stop

#endif//_EV_WRAP_H
