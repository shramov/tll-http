// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#include "tll-ev.h"

#include <tll/channel/base.h>
#include <tll/util/time.h>
#include <tll/util/scoped_fd.h>
#include <tll/util/pointer_list.h>
#include <memory>

#include <sys/timerfd.h>

template <typename T, typename E>
class EVCommon : public tll::channel::Base<T>
{
 protected:
	using Base = tll::channel::Base<T>;
	using Event = E;

	tll::util::PointerList<Event> _ev;
	tll_ev_loop * _loop = nullptr;

 public:
	static constexpr std::string_view channel_protocol() { return "ev"; }
	static constexpr auto process_protocol() { Base::ProcessPolicy::Manual; }

	void start(tll_ev_loop * loop, Event * ev)
	{
		_loop = loop;
		_ev.insert(ev);
		ev->self = this->self();
	}

	void stop(Event * ev)
	{
		//this->_log.error("Stop: {}", (void *) ev);
		_ev.erase_shrink(ev);
		if (!_ev.size()) {
			this->_log.warning("Disable");
			this->_update_dcaps(0, tll::dcaps::Process | tll::dcaps::CPOLLMASK);
		}
	}

	int _process(long timeout, int flags)
	{
		tll_ev_now_update(_loop);
		//this->_log.warning("Process: {}, events: {}, dcaps: {}", flags, events, this->internal.dcaps & tll::dcaps::CPOLLMASK);
		for (auto e : _ev) {
			if (e)
				e->cb(_loop, e, 0);
		}
		return 0;
	}
};

class EVIO : public EVCommon<EVIO, tll_ev_io>
{
	using Base = EVCommon<EVIO, tll_ev_io>;
 public:
	void start(tll_ev_loop * loop, Event * ev)
	{
		//_log.error("Start: {}", (void *) ev);
		Base::start(loop, ev);

		if (fd() == -1)
			_update_fd(ev->fd);

		_update();
	}

	void stop(Event * ev)
	{
		Base::stop(ev);
		_update();
	}

	void _update()
	{
		unsigned dcaps = 0;
		if (_ev.size())
			dcaps |= tll::dcaps::Process;
		for (auto e : _ev) {
			if (!e)
				continue;
			if (e->events & EV_READ)
				dcaps |= tll::dcaps::CPOLLIN;
			if (e->events & EV_WRITE)
				dcaps |= tll::dcaps::CPOLLOUT;
		}
		//_log.error("Update dcaps: {}", dcaps);
		this->_update_dcaps(dcaps, tll::dcaps::Process | tll::dcaps::CPOLLMASK);
	}

	int _process(long timeout, int flags)
	{
		tll_ev_now_update(_loop);
		int events = 0; //flags & TLL_PROCESS_POLLMASK;
		if (!events) events = EV_READ | EV_WRITE;
		//this->_log.warning("Process: {}, events: {}, dcaps: {}", flags, events, this->internal.dcaps & tll::dcaps::CPOLLMASK);
		for (auto e : _ev) {
			if (e && e->events & events)
				e->cb(_loop, e, events);
		}
		return 0;
	}
};


class EVTimer : public EVCommon<EVTimer, tll_ev_timer>
{
	using Base = EVCommon<EVTimer, tll_ev_timer>;

	tll::util::ScopedFd _fd;
 public:
	int _init(const tll::Channel::Url &cfg, tll::Channel * master)
	{
		_fd.reset(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));

		return Base::_init(cfg, master);
	}

	 void start(tll_ev_loop * loop, Event * ev)
	 {
		Base::start(loop, ev);

		struct itimerspec its = {};
		its.it_value = {(long) ev->at, static_cast<long>(ev->at * 1000000000) % 1000000000};
		its.it_interval = {(long) ev->repeat, static_cast<long>(ev->repeat * 1000000000) % 1000000000};
		if (timerfd_settime(_fd, 0, &its, nullptr))
			this->_log.error("Failed to set timer");

		this->_update_fd(_fd);
		this->_update_dcaps(tll::dcaps::Process | tll::dcaps::CPOLLIN);
	}

	int _process(long timeout, int flags)
	{
		uint64_t w;
		if (read(_fd, &w, sizeof(w))) {}
		return Base::_process(timeout, flags);
	}

};

TLL_DEFINE_IMPL(EVTimer);
TLL_DEFINE_IMPL(EVIO);

template <typename T> struct EVImpl {};
template <> struct EVImpl<tll_ev_io> { using Impl = EVIO; };
template <> struct EVImpl<tll_ev_timer> { using Impl = EVTimer; };

struct tll_ev_loop
{
	tll_channel_internal_t * internal = nullptr;
	double now = 0;

	std::list<std::unique_ptr<tll::Channel>> channels;
	std::map<int, tll::Channel *> fdmap;

	void reset()
	{
		channels.clear();
	}

	template <typename T>
	tll::Channel * tll_ev_init(T * ev)
	{
		using Impl = typename EVImpl<T>::Impl;

		if constexpr (std::is_same_v<T, tll_ev_io>) {
			if (auto it = fdmap.find(ev->fd); it != fdmap.end())
				return it->second;
		}

		tll::Logger _log(internal->logger);
		tll::Channel::Url curl;
		curl.proto("ev");
		curl.set("tll.internal", "yes");
		curl.set("name", fmt::format("{}/event/{}", internal->name, channels.size()));
		std::unique_ptr<tll::Channel> c { (tll::Channel *) tll_channel_new_url(internal->self->context, curl, nullptr, &Impl::impl) };
		if (!c)
			return _log.fail(nullptr, "Failed to create event channel");
		if (c->open())
			return _log.fail(nullptr, "Failed to open wrapper channel");
		if (auto r = tll_channel_internal_child_add(internal, c.get(), nullptr, 0))
			return _log.fail(nullptr, "Failed to add child channel {}: {}", tll_channel_name(c.get()), strerror(r));
		channels.emplace_back(std::move(c));
		if constexpr (std::is_same_v<T, tll_ev_io>) {
			fdmap.emplace(ev->fd, channels.back().get());
		}
		return channels.back().get();
	}
};

void tll_ev_now_update(tll_ev_loop * loop)
{
	using namespace std::chrono;
	loop->now = time_point_cast<duration<double>>(tll::time::now_cached()).time_since_epoch().count();
}

tll_ev_tstamp tll_ev_now(tll_ev_loop * loop)
{
	return loop->now;
}

tll_ev_loop * tll_ev_loop_new(tll_channel_internal_t * internal)
{
	return new tll_ev_loop { .internal = internal };
}

void tll_ev_loop_destroy(tll_ev_loop * loop)
{
	delete loop;
}

template <typename T>
void _ev_start(struct tll_ev_loop * loop, T * ev)
{
	if (!ev->self) {
		if (ev->self = loop->tll_ev_init(ev); !ev->self)
			return;
	}
	if (auto c = tll::channel_cast<typename EVImpl<T>::Impl>(ev->self); c)
		c->start(loop, ev);
}

template <typename T>
void _ev_stop(struct tll_ev_loop * loop, T * ev)
{
	if (auto c = tll::channel_cast<typename EVImpl<T>::Impl>(ev->self); c)
		c->stop(ev);
}

void tll_ev_timer_init(tll_ev_timer *ev, tll_ev_timer_cb_t cb, double at, double repeat)
{
	ev->self = nullptr;
	ev->cb = cb;
	ev->at = at;
	ev->repeat = repeat;
}

void tll_ev_timer_start(struct tll_ev_loop * loop, tll_ev_timer * ev) { _ev_start(loop, ev); }
void tll_ev_timer_stop(struct tll_ev_loop * loop, tll_ev_timer * ev) { _ev_stop(loop, ev); }

void tll_ev_io_init(tll_ev_io *ev, tll_ev_io_cb_t cb, int fd, int events)
{
	ev->self = nullptr;
	ev->cb = cb;
	ev->fd = fd;
	ev->events = events;
}

void tll_ev_io_start(struct tll_ev_loop * loop, tll_ev_io * ev) { _ev_start(loop, ev); }
void tll_ev_io_stop(struct tll_ev_loop * loop, tll_ev_io * ev) { _ev_stop(loop, ev); }
