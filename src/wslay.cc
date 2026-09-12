// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#include <tll/channel/prefix.h>
#include <tll/channel/module.h>
#include <tll/util/time.h>
#include <tll/util/bin2ascii.h>

#include <wslay/wslay.h>
#include "uwsc-scheme.h"

#include <chrono>

#include <sys/random.h>
#include <unistd.h>

using namespace std::chrono_literals;

class WSLay : public tll::channel::Prefix<WSLay>
{
	using Base = tll::channel::Prefix<WSLay>;

	tll_msg_t _msg = { .type = TLL_MESSAGE_DATA };
	uint8_t _ws_op = WSLAY_BINARY_FRAME;

	struct wslay_event_context * _client = nullptr;
	std::string_view _buf;

	std::string _host, _path, _path_suffix, _hostname;
	tll::duration _ping_interval = 3s;
	std::chrono::time_point<std::chrono::steady_clock> _ping_ts = {};
	bool _report_ping = false;

	using Headers = std::map<std::string, std::string>;
	Headers _headers;
	std::string _headers_str;

	std::unique_ptr<tll::Channel> _timer;
public:
	static constexpr std::string_view channel_protocol() { return "wslay+"; }
	static constexpr auto child_policy() { return ChildPolicy::Many; }
	static constexpr auto open_policy() { return OpenPolicy::Manual; }
	static constexpr auto process_policy() { return ProcessPolicy::Never; }
	static constexpr auto scheme_control_string() { return uwsc_scheme::scheme_string; }
	static constexpr auto prefix_active_policy() { return Base::PrefixActivePolicy::Manual; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close(bool force);

	int _post(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

	const tll::Scheme * scheme(int type) const
	{
		if (type == TLL_MESSAGE_CONTROL)
			return _scheme_control.get();
		return Base::scheme(type);
	}

	int _on_init(tll::Channel::Url &curl, const tll::Channel::Url &, const tll::Channel *)
	{
		curl.host(_host);
		return 0;
	}

	int _on_active();
	int _on_data(const tll_msg_t *);

private:
	void _on_ws_error(int err, const char * msg);
	void _on_ws_close(int code, std::string_view reason);
	void _on_ws_message(const wslay_event_on_msg_recv_arg *);
	void _on_ws_control(int op);
	int _ping();

	int _on_recv_buf(std::string_view);
	int _on_timer(const tll::Channel *, const tll_msg_t *)
	{
		_ping_ts = std::chrono::steady_clock::now();
		wslay_event_msg frame = { .opcode = WSLAY_PING };
		if (auto r = wslay_event_queue_msg(_client, &frame); r)
			return _log.fail(EINVAL, "Failed to queue ping message: {}", r);
		if (auto r = wslay_event_send(_client); r)
			return state_fail(EINVAL, "wslay_event_send failed: {}", r);
		return 0;
	}

	ssize_t _on_recv(wslay_event_context * ctx, uint8_t *buf, size_t len, int flags);
	ssize_t _on_send(wslay_event_context * ctx, const uint8_t *buf, size_t len, int flags);

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

	int _handshake(const tll_msg_t * msg);
};

using namespace tll;

int WSLay::_init(const tll::Channel::Url &url, tll::Channel *master)
{
	auto reader = channel_props_reader(url);
	_hostname = reader.getT("hostname", std::string{});
	_ping_interval = reader.getT<tll::duration>("ping", 3s);
	_report_ping = reader.getT("report-ping", false);
	_ws_op = reader.getT("binary", true) ? WSLAY_BINARY_FRAME : WSLAY_TEXT_FRAME;
	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	if (_ping_interval.count() > 0) {
		auto turl = child_url_parse("timer://", "timer");
		if (!turl)
			return _log.fail(EINVAL, "Failed to parse timer url: {}", turl.error());
		turl->set("interval", tll::conv::to_string(_ping_interval));
		_timer = context().channel(*turl);
		if (!_timer)
			return _log.fail(EINVAL, "Failed to init timer channel");
		_timer->callback_add<WSLay, &WSLay::_on_timer>(this, TLL_MESSAGE_MASK_DATA);
		_child_add(_timer.get(), "timer");
	}

	if (auto hcfg = url.sub("header"); hcfg)
		_fill_headers(_headers, *hcfg);

	_host = url.host();
	if (auto sep = _host.find('/'); sep != _host.npos) {
		_path = _host.substr(sep);
		_host = _host.substr(0, sep);
	}

	return Base::_init(url, master);
}

int WSLay::_open(const tll::ConstConfig &cfg)
{
	Headers headers = _headers;
	if (auto hcfg = cfg.sub("header"); hcfg)
		_fill_headers(headers, *hcfg);
	_headers_str.clear();
	for (auto & [h, v] : headers)
		_headers_str += fmt::format("{}: {}\r\n", h, v);

	wslay_event_callbacks callbacks = {
	    .recv_callback = [](wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags,
	                        void *user_data) { return static_cast<WSLay *>(user_data)->_on_recv(ctx, buf, len, flags); },
	    .send_callback = [](wslay_event_context_ptr ctx, const uint8_t *buf, size_t len, int flags,
	                        void *user_data) { return static_cast<WSLay *>(user_data)->_on_send(ctx, buf, len, flags); },
	    // Always called for 4 byte buffer, crypto level randomness is not needed
	    .genmask_callback =
	        [](auto, uint8_t *buf, auto, auto) {
		        *(int *)buf = rand();
		        return 0;
	        },
	    .on_msg_recv_callback = [](wslay_event_context_ptr ctx, const wslay_event_on_msg_recv_arg *arg,
	                               void *user_data) { static_cast<WSLay *>(user_data)->_on_ws_message(arg); },
	};

	if (auto r = wslay_event_context_client_init(&_client, &callbacks, this); r)
		return _log.fail(EINVAL, "Failed to initialize wslay context: {}", r);

	_path_suffix.clear();
	if (auto path = cfg.get("path"); path)
		_path_suffix = *path;

	_log.info("Connect to {}{}{}", _host, _path, _path_suffix);

	return Base::_open(cfg);
}

int WSLay::_close(bool force)
{
	if (auto r = _child->close(force); r)
		return r;

	if (_client)
		wslay_event_context_free(_client);
	_client = nullptr;
	if (_timer)
		_timer->close();

	return 0;
}

int WSLay::_post(const tll_msg_t *msg, int flags)
{
	if (msg->type != TLL_MESSAGE_DATA)
		return 0;
	wslay_event_msg frame = {
		.opcode = _ws_op,
		.msg = (const uint8_t *) msg->data,
		.msg_length = msg->size,
	};
	if (auto r = wslay_event_queue_msg(_client, &frame); r)
		return _log.fail(EINVAL, "Failed to queue message: {}", r);
	if (flags & TLL_POST_MORE)
		return 0;
	if (auto r = wslay_event_send(_client); r)
		return state_fail(EINVAL, "wslay_event_send failed: {}", r);
	return 0;
}

int WSLay::_process(long timeout, int flags)
{
	if (state() == tll::state::Closing)
		close(true);

	return 0;
}

void WSLay::_on_ws_error(int err, const char * msg)
{
	_log.error("Error occurred: {}", msg);
	if (_timer)
		_timer->close();
	state(tll::state::Error);
}

void WSLay::_on_ws_close(int code, std::string_view reason)
{
	_log.info("Connection closed: {} {}", code, reason);
	if (_timer)
		_timer->close();
	wslay_event_send(_client); // Send close frame to the server
	state(tll::state::Closing);
	_update_dcaps(dcaps::Process | dcaps::Pending);
}


void WSLay::_on_ws_message(const wslay_event_on_msg_recv_arg *arg)
{
	switch (arg->opcode) {
	case WSLAY_BINARY_FRAME:
	case WSLAY_TEXT_FRAME:
		_msg.data = arg->msg;
		_msg.size = arg->msg_length;
		_callback_data(&_msg);
		break;
	case WSLAY_PING:
	case WSLAY_PONG:
		return _on_ws_control(arg->opcode);
	case WSLAY_CONNECTION_CLOSE:
		return _on_ws_close(arg->status_code, {(const char *) arg->msg, arg->msg_length });
	}
}

/*
int WSLay::_ping(uwsc_client *c)
{
	static constexpr std::string_view msg = "libuwsc";
	_ping_ts = std::chrono::steady_clock::now();
	return c->send(c, msg.data(), msg.size(), UWSC_OP_PING);
}
*/

void WSLay::_on_ws_control(int op)
{
	if (!_report_ping)
		return;
	tll_msg_t msg = { .type = TLL_MESSAGE_CONTROL, .msgid = op };
	if (op == WSLAY_PONG) {
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

ssize_t WSLay::_on_recv(wslay_event_context * ctx, uint8_t *buf, size_t len, int flags)
{
	if (_buf.empty()) {
		wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
		return -1;
	}
	len = std::min(len, _buf.size());
	memcpy(buf, _buf.data(), len);
	_buf = _buf.substr(len);
	return len;
}

ssize_t WSLay::_on_send(wslay_event_context * ctx, const uint8_t *buf, size_t len, int flags)
{
	tll_msg_t msg = { .type = TLL_MESSAGE_DATA, .data = buf, .size = len };
	if (auto r = _child->post(&msg, (flags & WSLAY_MSG_MORE) ? TLL_POST_MORE : 0); r) {
		wslay_event_set_error(ctx, r == EAGAIN ? WSLAY_ERR_WOULDBLOCK : WSLAY_ERR_CALLBACK_FAILURE);
		return -1;
	} else
		return len;
}

int WSLay::_on_active()
{
	using namespace std::literals::string_view_literals;
	std::string key = "AAAAAAAAAAAAAAAAAAAAAA==";
	std::string keyresp = "mMUdnrWkqg9evVAwThfwMU3nxG0=";

#if FMT_VERSION < 80000
	struct memory_buffer : public fmt::memory_buffer
	{
		void append(const std::string_view &v) { fmt::memory_buffer::append(v.data(), v.data() + v.size()); }
	};
#else
	using fmt::memory_buffer;
#endif

	auto buf = memory_buffer();
	buf.append(std::string_view("GET "));
	if (_path.empty() && _path_suffix.empty()) {
		buf.append("/"sv);
	} else {
		buf.append(_path);
		buf.append(_path_suffix);
	}
	buf.append(" HTTP/1.1\r\n"sv);
	std::string_view host = _hostname.size() ? _hostname : _host;
	fmt::format_to(std::back_inserter(buf),
		"Host: {}\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: {}\r\n"
		"Sec-WebSocket-Version: 13\r\n",
		host, key);
	if (_headers_str.size())
		buf.append(_headers_str);
	buf.append("\r\n"sv);
	tll_msg_t msg = { .type = TLL_MESSAGE_DATA, .data = buf.data(), .size = buf.size() };
	if (auto r = _child->post(&msg); r)
		return _log.fail(EINVAL, "Failed to post initial handshake");
	return Base::_on_active();
}

int WSLay::_handshake(const tll_msg_t * msg)
{
	// TODO: Handle fragmented response
	std::string_view data { (const char*) msg->data, msg->size };
	constexpr std::string_view expect = "HTTP/1.1 101";
	auto sep = data.find("\r\n\r\n");
	if (sep == data.npos)
		return state_fail(EINVAL, "Data without end marker");
	auto reply = data.substr(0, sep);
	if (reply.substr(0, expect.size()) != expect)
		return state_fail(EINVAL, "Invalid reply: {}", reply);
	_log.info("Connection established");
	if (_timer)
		_timer->open();
	state(tll::state::Active);
	return _on_recv_buf(data.substr(sep + 4));
}

int WSLay::_on_data(const tll_msg_t * msg)
{
	_msg.time = msg->time;
	if (state() == tll::state::Opening)
		return _handshake(msg);
	return _on_recv_buf({ (const char *) msg->data, msg->size });
}

int WSLay::_on_recv_buf(std::string_view data)
{
	if (data.empty())
		return 0;
	_buf = data;
	auto r = wslay_event_recv(_client);
	_buf = {};
	if (r)
		return _log.fail(EINVAL, "wslay_event_recv failed: {}", r);
	return 0;
}

TLL_DEFINE_IMPL(WSLay);

static int _init(tll_channel_module_t *, tll_channel_context_t * ctx, const tll_config_t *)
{
	if (auto r = tll_channel_impl_register(ctx, &WSLay::impl, nullptr); r)
		return r;
	if (auto r = tll_channel_alias_register(ctx, "ws", "wslay+tcp://;frame=none", -1); r)
		return r;
	if (auto r = tll_channel_alias_register(ctx, "wss", "wslay+tls://;frame=none", -1); r)
		return r;
	return 0;
};

extern "C" tll_channel_module_t * tll_channel_module()
{
	static tll_channel_module_t mod = { .init = _init };
	return &mod;
}
