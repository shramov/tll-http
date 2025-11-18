/*
 * Copyright (c) 2021 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <tll/channel/base.h>
#include <tll/channel/module.h>
#include <tll/util/scoped_fd.h>
#include <tll/util/sockaddr.h>
#include <tll/util/time.h>

#include "uwsc.h"
#include "log.h"
#include "ev-backend.h"
#include "uwsc-scheme.h"

#include <chrono>

#include <sys/timerfd.h>
#include <unistd.h>

using namespace std::chrono_literals;

class WSClient : public tll::channel::Base<WSClient>
{
	tll::util::ScopedFd _timerfd { -1 };
	int _ws_op = UWSC_OP_BINARY;

	struct uwsc_client * _client = nullptr;

	struct ev_loop * _ev_loop = nullptr;
	struct ev_io _ev_timer = {};

	std::string _url;
	std::chrono::seconds _ping_interval = 3s;
	std::chrono::time_point<std::chrono::steady_clock> _ping_ts = {};
	bool _report_ping = false;

	using Headers = std::map<std::string, std::string>;
	Headers _headers;

public:
	static constexpr std::string_view channel_protocol() { return "ws"; }
	static constexpr auto open_policy() { return OpenPolicy::Manual; }
	static constexpr auto scheme_control_string() { return uwsc_scheme::scheme_string; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	void _free()
	{
		uwsc_logger_unref();
	}

	int _open(const tll::ConstConfig &);
	int _close();

	int _process(long timeout, int flags);
	int _post(const tll_msg_t *msg, int flags);

private:
	void _on_open(uwsc_client *c);
	void _on_error(uwsc_client *c, int err, const char * msg);
	void _on_close(uwsc_client *cl, int code, const char * reason);
	void _on_message(uwsc_client *c, void *data, size_t len, bool binary);
	void _on_control(uwsc_client *c, int op);
	int _ping(uwsc_client *c);

	void _fill_headers(Headers &headers, tll::ConstConfig &config)
	{
		for (auto & [hdr, cfg] : config.browse("**")) {
			auto v = cfg.get();
			if (!v || !v->size())
				continue;
			_log.debug("Extra header: {}: {}", hdr, *v);
			headers[hdr] = *v;
		}
	}
	int _export_address(uwsc_client *c, bool local);
};

using namespace tll;

int WSClient::_init(const tll::Channel::Url &url, tll::Channel *master)
{
	auto reader = channel_props_reader(url);
	_ping_interval = reader.getT("ping", 3s);
	_report_ping = reader.getT("report-ping", false);
	_ws_op = reader.getT("binary", true) ? UWSC_OP_BINARY : UWSC_OP_TEXT;
	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	if (auto hcfg = url.sub("header"); hcfg)
		_fill_headers(_headers, *hcfg);

	_url = fmt::format("{}://{}", url.proto(), url.host());

	uwsc_logger_ref();

	return Base<WSClient>::_init(url, master);
}

int WSClient::_open(const tll::ConstConfig &url)
{
	Headers headers = _headers;
	if (auto hcfg = url.sub("header"); hcfg)
		_fill_headers(headers, *hcfg);
	std::string hstring;
	for (auto & [h, v] : headers)
		hstring += fmt::format("{}: {}\r\n", h, v);

	_timerfd.reset(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
	if (_timerfd == -1)
		return _log.fail(EINVAL, "Failed to create timer fd: {}", strerror(errno));

	_ev_loop = ev_loop_new(EVFLAG_NOENV | EVFLAG_NOSIGMASK);
	if (!_ev_loop)
		return _log.fail(EINVAL, "Faield to init libev event loop");

	ev_io_init(&_ev_timer,
		[](struct ev_loop *, ev_io *ev, int)
		{
			int64_t buf;
			auto r = read(ev->fd, &buf, sizeof(buf));
			(void) r;
		},
		_timerfd,
		EV_READ);
	ev_io_start(_ev_loop, &_ev_timer);

	ev_run(_ev_loop, EVRUN_NOWAIT);

	struct itimerspec its = {};
	its.it_interval = { 0, 10000000 };
	its.it_value = { 0, 1 };
	if (timerfd_settime(_timerfd, 0, &its, nullptr))
		return _log.fail(EINVAL, "Failed to rearm timerfd: {}", strerror(errno));

	_client = uwsc_new(_ev_loop, _url.c_str(), _ping_interval.count(), hstring.size() ? hstring.c_str() : nullptr);
	if (!_client)
		return _log.fail(EINVAL, "Failed to init uwsc client");

	_client->ext = this;
	_client->onopen = [](uwsc_client *c) { static_cast<WSClient *>(c->ext)->_on_open(c); };
	_client->onerror = [](uwsc_client *c, int e, const char *m) { static_cast<WSClient *>(c->ext)->_on_error(c, e, m); };
	_client->onclose = [](uwsc_client *c, int e, const char *m) { static_cast<WSClient *>(c->ext)->_on_close(c, e, m); };
	_client->onmessage = [](uwsc_client *c, void *d, size_t l, bool b) { static_cast<WSClient *>(c->ext)->_on_message(c, d, l, b); };
	if (_report_ping) {
		_client->ping = [](uwsc_client *c) { static_cast<WSClient *>(c->ext)->_ping(c); };
		_client->onping = [](uwsc_client *c) { static_cast<WSClient *>(c->ext)->_on_control(c, UWSC_OP_PING); };
		_client->onpong = [](uwsc_client *c) { static_cast<WSClient *>(c->ext)->_on_control(c, UWSC_OP_PONG); };
	}

	auto fd = tll_ev_backend_fd(_ev_loop);

	if (fd != -1) {
		_update_fd(fd);
		_update_dcaps(dcaps::CPOLLIN);
	}

	return 0;
}

int WSClient::_close()
{
	this->_update_fd(-1);

	if (_client) {
		if (_client->free)
			_client->free(_client);
		::free(_client);
	}
	_client = nullptr;

	if (_ev_loop)
		ev_loop_destroy(_ev_loop);
	_ev_loop = nullptr;

	_timerfd.reset();

	return 0;
}

int WSClient::_post(const tll_msg_t *msg, int flags)
{
	if (msg->type != TLL_MESSAGE_DATA)
		return 0;
	_client->send(_client, msg->data, msg->size, _ws_op);
	return 0;
}

int WSClient::_process(long timeout, int flags)
{
	_log.trace("Process");
	if (state() == tll::state::Closing) {
		close(true);
		return 0;
	}

	auto r = ev_run(_ev_loop, EVRUN_NOWAIT);
	if (r < 0)
		return _log.fail(EINVAL, "ev_run failed: {}", r);
	return 0;
}

int WSClient::_export_address(uwsc_client *c, bool local)
{
	const std::string_view path = local ? "local" : "remote";

	tll::network::sockaddr_any addr;
	addr.size = sizeof(addr);
	const auto func = local ? getsockname : getpeername;
	if (func(c->sock, addr, &addr.size))
		return _log.fail(errno, "Failed to get {} address: {}", path, strerror(errno));

	this->_log.debug("Export {} address: {}", path, addr);
	auto cfg = this->config_info().sub(path, true);
	if (!cfg)
		return this->_log.fail(EINVAL, "Can not create subtree for {} address", path);
	cfg->setT("af", (network::AddressFamily) addr->sa_family);
	cfg->setT("port", ntohs(addr.in()->sin_port));
	if (addr->sa_family == AF_INET)
		cfg->setT("host", addr.in()->sin_addr);
	else
		cfg->setT("host", addr.in6()->sin6_addr);

	return 0;
}

void WSClient::_on_open(uwsc_client *c)
{
	_log.info("Connection established");

	if (_export_address(c, true) || _export_address(c, false)) {
		state(tll::state::Error);
		return;
	}

	state(tll::state::Active);
}

void WSClient::_on_error(uwsc_client *c, int err, const char * msg)
{
	_log.error("Error occured: {}", msg);
	// Client structure is cleared (but not zeroed) on error
	memset(_client, 0, sizeof(*_client));
	state(tll::state::Error);
}

void WSClient::_on_close(uwsc_client *cl, int code, const char * reason)
{
	_log.info("Connection closed: {} {}", code, reason);
	_client = nullptr;
	state(tll::state::Closing);
	_dcaps_pending(true);
}

void WSClient::_on_message(uwsc_client *c, void *data, size_t len, bool binary)
{
	tll_msg_t msg = {};
	msg.type = TLL_MESSAGE_DATA;
	msg.data = data;
	msg.size = len;
	_callback_data(&msg);
}

int WSClient::_ping(uwsc_client *c)
{
	static constexpr std::string_view msg = "libuwsc";
	_ping_ts = std::chrono::steady_clock::now();
	return c->send(c, msg.data(), msg.size(), UWSC_OP_PING);
}

void WSClient::_on_control(uwsc_client *c, int op)
{
	tll_msg_t msg = { .type = TLL_MESSAGE_CONTROL, .msgid = op };
	if (op == UWSC_OP_PONG) {
		std::array<char, uwsc_scheme::Pong::meta_size()> buf;
		auto data = uwsc_scheme::Pong::bind(buf);
		auto dt = std::chrono::steady_clock::now() - _ping_ts;
		data.set_rtt(dt);
		msg.data = data.view().data();
		msg.size = data.view().size();
		_callback(&msg);
	} else
		_callback(&msg);
}

struct WSSClient : public WSClient { static tll::channel_impl<WSSClient> impl; };

TLL_DEFINE_IMPL(WSClient);
tll::channel_impl<WSSClient> WSSClient::impl = {"wss"};

TLL_DEFINE_MODULE(WSClient, WSSClient);
