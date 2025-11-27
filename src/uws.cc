/*
 * Copyright (c) 2021 Pavel Shramov <shramov@mexmat.net>
 *
 * tll is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "App.h"

#include <variant>

#include "tll/channel/base.h"
#include "tll/channel/module.h"
#include "tll/util/cppring.h"
#include "tll/util/size.h"
#include "tll/util/sockaddr.h"

#include "ws-scheme.h"
#include "http-status.h"
#include "uws-epoll.h"

using namespace tll;
using Method = ws_scheme::Method;

class WSHTTP;
class WSWS;
class WSPub;

struct User {
	std::variant<WSWS *, WSPub *> channel;
	tll::util::DataRing<void>::iterator position; // For pub nodes
	tll_addr_t addr;
};

using WebSocket = uWS::WebSocket<false, true, User>;

class WSServer : public tll::channel::Base<WSServer>
{
	using node_ptr_t = std::variant<WSHTTP *, WSWS *, WSPub *>;
	using NodeMap = std::map<std::string_view, node_ptr_t, std::less<>>;
	NodeMap _nodes;
	NodeMap _nodes_wildcard;

	static thread_local WSServer * _instance;

	std::unique_ptr<uWS::App> _app;
	us_listen_socket_t * _app_socket = nullptr;
	uWS::Loop * _app_loop = nullptr;

	std::string _host;
	unsigned short _port;
	size_t _max_payload_size = 16 * 1024;
	size_t _sndbuf = 0;
	size_t _rcvbuf = 0;

 public:
	uWS::OpCode default_op_code = uWS::OpCode::BINARY;

	static constexpr std::string_view channel_protocol() { return "uws"; }

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();
	void _free()
	{
		if (_instance == this)
			_instance = nullptr;
	}

	int _process(long timeout, int flags);

	template <typename T>
	int node_add(std::string_view prefix, T * ptr)
	{
		if (ptr->wildcard)
			return node_add(_nodes_wildcard, prefix, ptr);
		return node_add(_nodes, prefix, ptr);
	}

	template <typename T>
	int node_remove(std::string_view prefix, T * ptr)
	{
		if (ptr->wildcard)
			return node_remove(_nodes_wildcard, prefix, ptr);
		return node_remove(_nodes, prefix, ptr);
	}

	node_ptr_t * node_lookup(std::string_view uri)
	{
		auto it = _nodes.find(uri);
		if (it != _nodes.end())
			return &it->second;
		it = _nodes_wildcard.upper_bound(uri);
		if (it == _nodes_wildcard.begin())
			return nullptr;
		--it;
		if (uri.substr(0, it->first.size()) == it->first)
			return &it->second;
		return nullptr;
	}

	template <typename T>
	int node_add(NodeMap &nodes, std::string_view prefix, T * ptr)
	{
		auto it = nodes.find(prefix);
		if (it != nodes.end())
			return EEXIST;
		_log.info("Add new {} node {} at {}", T::channel_protocol(), ptr->name, prefix);
		nodes.emplace(prefix, ptr);
		return 0;
	}

	template <typename T>
	int node_remove(NodeMap &nodes, std::string_view prefix, T * ptr)
	{
		auto it = nodes.find(prefix);
		if (it == nodes.end())
			return ENOENT;
		if (!std::holds_alternative<T *>(it->second))
			return EINVAL;
		if (std::get<T *>(it->second) != ptr)
			return EINVAL;
		nodes.erase(it);
		return 0;
	}

 private:

	template <Method M>
	void _http(uWS::HttpResponse<false> * resp, uWS::HttpRequest *req);
	void _ws_upgrade(uWS::HttpResponse<false> * resp, uWS::HttpRequest *req, us_socket_context_t *context);
	void _ws_open(WebSocket *);
	void _ws_message(WebSocket *, std::string_view, uWS::OpCode);
	void _ws_drain(WebSocket *);
	void _ws_close(WebSocket *, int code, std::string_view message);
};

thread_local WSServer * WSServer::_instance = nullptr;

template <typename T, typename R = uWS::HttpResponse<false>>
class WSNode : public tll::channel::Base<T>
{
 protected:
	WSServer * _master = nullptr;
	using Base = tll::channel::Base<T>;

	std::string _prefix;
	uWS::OpCode _op_code;

	std::map<uint64_t, R *> _sessions;
	tll_addr_t _addr;

 public:
	static constexpr std::string_view param_prefix() { return "uws"; }
	static constexpr auto process_policy() { return Base::ProcessPolicy::Never; }

	bool wildcard = false;

	int _init(const tll::Channel::Url &, tll::Channel *master);
	int _open(const tll::ConstConfig &);
	int _close();

	int _post_data(R * resp, const tll_msg_t *msg, int flags)
	{
		resp->writeStatus(uWS::HTTP_200_OK);
		resp->end(std::string_view((const char *) msg->data, msg->size));
		_sessions.erase(msg->addr.u64);
		return 0;
	}

	int _post_control(R * resp, const tll_msg_t *msg, int flags)
	{
		if (msg->msgid != ws_scheme::Disconnect::meta_id())
			return 0;
		_disconnected(resp, msg->addr);
		resp->end();
		return 0;
	}

	int _post(const tll_msg_t *msg, int flags)
	{
		auto it = _sessions.find(msg->addr.u64);
		if (it == _sessions.end())
			return this->_log.fail(ENOENT, "Failed to post: session 0x{:x} not found", msg->addr.u64);

		if (msg->type == TLL_MESSAGE_DATA)
			return static_cast<T *>(this)->_post_data(it->second, msg, flags);
		else if (msg->type == TLL_MESSAGE_CONTROL)
			return static_cast<T *>(this)->_post_control(it->second, msg, flags);
		return 0;
	}

	int _connected(R * resp, std::string_view url, tll_addr_t * addr, Method method = Method::UNDEFINED);
	int _disconnected(R * resp, tll_addr_t addr);

 protected:
	tll_addr_t _next_addr()
	{
		return { ++_addr.u64 }; // TODO: Check for duplicates
	}
};

class WSHTTP : public WSNode<WSHTTP>
{
 public:
	static constexpr std::string_view channel_protocol() { return "uws+http"; }

	int _post_control(uWS::HttpResponse<false> * resp, const tll_msg_t *msg, int flags)
	{
		switch (msg->msgid) {
		case ws_scheme::Connect::meta_id():
			return _post_connect(resp, msg);
		case ws_scheme::Disconnect::meta_id():
			resp->end();
			_disconnected(nullptr, msg->addr);
			break;
		default:
			_log.warning("Unsupported control message {}", msg->msgid);
			break;
		}
		return 0;
	}

	int _post_connect(uWS::HttpResponse<false> * resp, const tll_msg_t *msg)
	{
		auto data = ws_scheme::Connect::bind(*msg);
		if (msg->size < data.meta_size())
			return _log.fail(EMSGSIZE, "Connect size too small: {} < minimum {}", msg->size, data.meta_size());
		if (auto status = http_status_string(data.get_code() != 0 ? data.get_code() : 200); status != "")
			resp->writeStatus(status);
		else
			return _log.fail(EINVAL, "Undefined HTTP status code: {}", data.get_code());
		for (auto & h : data.get_headers())
			resp->writeHeader(h.get_header(), h.get_value());
		return 0;
	}
};

class WSWS : public WSNode<WSWS, WebSocket>
{
 public:
	using Response = WebSocket;

	static constexpr std::string_view channel_protocol() { return "uws+ws"; }

	int _post_data(Response * resp, const tll_msg_t *msg, int flags)
	{
		resp->send(std::string_view((const char *) msg->data, msg->size), _op_code);
		return 0;
	}

	int _post_control(Response * resp, const tll_msg_t *msg, int flags)
	{
		if (msg->msgid != ws_scheme::Disconnect::meta_id())
			return 0;
		resp->end();
		_disconnected(nullptr, msg->addr);
		return 0;
	}
};

class WSPub : public WSNode<WSPub, WebSocket>
{
	tll::util::DataRing<void> _ring;
 public:
	using Response = WebSocket;
	using Parent = WSNode<WSPub, Response>;

	static constexpr std::string_view channel_protocol() { return "uws+pub"; }

	int _init(const tll::Channel::Url &url, tll::Channel *master)
	{
		if (auto r = Parent::_init(url, master); r)
			return r;

		auto reader = channel_props_reader(url);

		auto size = reader.getT<size_t>("ring-size", 1024);
		auto data = reader.getT<tll::util::Size>("data-size", 1024 * 1024);

		if (!reader)
			return _log.fail(EINVAL, "Invalid url: {}", reader.error());

		_ring.resize(size);
		_ring.data_resize(data);
		return 0;
	}

	int _open(const tll::ConstConfig &url)
	{
		_ring.clear();
		return Parent::_open(url);
	}

	int _post_data(Response * resp, const tll_msg_t *msg, int flags)
	{
		if (msg->size > _ring.data_capacity() / 2)
			return _log.fail(EINVAL, "Message size {} is larger then half of buffer: {}", msg->size, _ring.data_capacity());
		auto last = _ring.end();
		do {
			auto r = _ring.push_back(msg->data, msg->size);
			if (r != nullptr)
				break;
			auto first = _ring.begin();
			_ring.pop_front();

			auto it = _sessions.begin();
			while (it != _sessions.end()) {
				auto [addr, ws] = *(it++); // Close will remove element
				auto user = ws->getUserData();
				_log.info("Session {} is behind data, closing", addr);
				if (user->position == first)
					ws->close();
			}
		} while (true);

		for (auto &[a, ws] : _sessions) {
			auto user = ws->getUserData();
			if (user->position == last)
				writeable(ws, user);
		}
		return 0;
	}

	int _post_control(Response * resp, const tll_msg_t *msg, int flags)
	{
		if (msg->msgid != ws_scheme::Disconnect::meta_id())
			return 0;
		resp->end();
		_disconnected(nullptr, msg->addr);
		return 0;
	}

	int _post(const tll_msg_t *msg, int flags)
	{
		if (msg->type == TLL_MESSAGE_DATA)
			return _post_data(nullptr, msg, flags);
		return Parent::_post(msg, flags);
	}

	int _connected(Response * ws, std::string_view url, tll_addr_t * addr)
	{
		auto user = ws->getUserData();
		user->position = _ring.end();

		return Parent::_connected(ws, url, addr);
	}

	void writeable(Response * ws, User * user)
	{
		if (ws->getBufferedAmount() > 0)
			return;
		if (user->position == _ring.end())
			return;

		_log.debug("Post data to {}", user->addr.u64);
		auto data = std::string_view((const char *) user->position->data(), user->position->size);
		user->position++;

		ws->send(data, _op_code);
	}
};

int WSServer::_init(const Channel::Url &url, Channel * master)
{
	//if (!url.host().size())
	//	return _log.fail(EINVAL, "No path to database");

	if (_instance)
		return _log.fail(EINVAL, "Only one UWS server per thread, blocked by existing: '{}'", _instance->name);

	_scheme_control.reset(context().scheme_load(ws_scheme::scheme_string));
	if (!_scheme_control.get())
		return _log.fail(EINVAL, "Failed to load control scheme");

	auto host = url.host();
	auto sep = host.find_last_of(':');
	if (sep == host.npos)
		return this->_log.fail(EINVAL, "Invalid host:port pair: {}", host);
	auto p = conv::to_any<unsigned short>(host.substr(sep + 1));
	if (!p)
		return this->_log.fail(EINVAL, "Invalid port '{}': {}", host.substr(sep + 1), p.error());

	_port = *p;
	_host = host.substr(0, sep);

	auto reader = channel_props_reader(url);
	default_op_code = reader.getT("binary", true) ? uWS::OpCode::BINARY : uWS::OpCode::TEXT;
	_max_payload_size = reader.getT<tll::util::Size>("max-payload-size", _max_payload_size);
	_sndbuf = reader.getT("sndbuf", tll::util::Size { 0 });
	_rcvbuf = reader.getT("rcvbuf", tll::util::Size { 0 });
	/*
	_table = reader.getT<std::string>("table");
	if ((internal.caps & (caps::Input | caps::Output)) == caps::Input)
		_autoclose = reader.getT("autoclose", false);
		*/
	if (!reader)
		return _log.fail(EINVAL, "Invalid url: {}", reader.error());

	_instance = this;
	return 0;
}

int WSServer::_open(const ConstConfig &s)
{
	_app_loop = uWS::Loop::get();
	_app_loop->integrate();

	auto us_loop = (us_loop_t *) _app_loop;
	auto fd = us_loop->fd;

	if (fd != -1) {
		_update_fd(fd);
		_update_dcaps(dcaps::CPOLLIN);
	}

	_app.reset(new uWS::App());
	uWS::App::WebSocketBehavior<User> wsopt = {};

	wsopt.compression = uWS::SHARED_COMPRESSOR;
	wsopt.maxPayloadLength = _max_payload_size;
	wsopt.idleTimeout = 10;
	wsopt.maxBackpressure = 1 * 1024 * 1024;

	/* Handlers */
	wsopt.upgrade = [this](auto *res, auto *req, auto *context) { return this->_ws_upgrade(res, req, context); };
	wsopt.open = [this](auto *ws) { this->_ws_open(ws); };
	wsopt.message = [this](auto *ws, std::string_view message, uWS::OpCode opCode) { this->_ws_message(ws, message, opCode); };
	wsopt.drain = [this](auto *ws) { this->_ws_drain(ws); };
	wsopt.close = [this](auto *ws, int code, std::string_view message) { this->_ws_close(ws, code, message); };

	_app->get("/*", [this](auto *res, auto *req) { this->_http<Method::GET>(res, req); })
		.post("/*", [this](auto *res, auto *req) { this->_http<Method::POST>(res, req); })
		.put("/*", [this](auto *res, auto *req) { this->_http<Method::PUT>(res, req); })
		.head("/*", [this](auto *res, auto *req) { this->_http<Method::HEAD>(res, req); })
		.options("/*", [this](auto *res, auto *req) { this->_http<Method::OPTIONS>(res, req); })
		.ws<User>("/*", std::move(wsopt))
		.listen(_port, [this](auto *token) {
			this->_app_socket = token;
			if (token) {
				this->_log.info("Serving");
			}
		});

	return 0;
}

int WSServer::_close()
{
	this->_update_fd(-1);

	for (auto it = _nodes.begin(); it != _nodes.end(); ) {
		_log.debug("Close child node {}", it->first);
		auto node = (it++)->second;
		std::visit([](auto && c) { c->close(); }, node);
	}

	_log.debug("Close US loop");

	if (_app_socket) {
		us_listen_socket_close(0, _app_socket);
		_app_socket = nullptr;
	}

	if (_app_loop) {
		for (auto i = 0u; i < 100; i++)
			us_loop_step((us_loop_t *) _app_loop, 0);

		_app.reset();
		for (auto i = 0u; i < 100; i++)
			us_loop_step((us_loop_t *) _app_loop, 0);

		_app_loop->free();
		_app_loop = nullptr;
	}

	return 0;
}

int WSServer::_process(long timeout, int flags)
{
	auto r = us_loop_step((us_loop_t *) _app_loop, 0);
	if (r < 0)
		return _log.fail(EINVAL, "UV run failed: {}", r);
	return 0;
}

template <typename T, typename R>
int WSNode<T, R>::_init(const Channel::Url &url, Channel * master)
{
	if (!master)
		return this->_log.fail(EINVAL, "WS node channel needs master");

	_master = channel_cast<WSServer>(master);
	if (!_master)
		return this->_log.fail(EINVAL, "Master {} must be ws:// channel", master->name());

	this->_op_code = _master->default_op_code;
	this->_scheme_control.reset(tll_scheme_ref(_master->_scheme_control.get()));

	_prefix = url.host();
	if (!_prefix.size())
		_prefix = "/";
	else if (_prefix[0] != '/')
		_prefix = "/" + _prefix;
	if (wildcard = (_prefix.back() == '*'); wildcard)
		_prefix = _prefix.substr(0, _prefix.size() - 1);
	return 0;
}

template <typename T, typename R>
int WSNode<T, R>::_open(const ConstConfig &props)
{
	if (_master->node_add(_prefix, static_cast<T *>(this)))
		return this->_log.fail(EINVAL, "Failed to register node");
	_addr = {};
	return 0;
}

template <typename T, typename R>
int WSNode<T, R>::_close()
{
	for (auto &[a, r] : _sessions)
		r->close();
	_sessions.clear();
	_master->node_remove(_prefix, static_cast<T *>(this));
	return 0;
}

template <typename T, typename R>
int WSNode<T, R>::_connected(R * resp, std::string_view uri, tll_addr_t * addr, Method method)
{
	std::vector<unsigned char> buf;
	auto data = ws_scheme::Connect::bind(buf);
	buf.resize(data.meta_size());

	data.set_path(uri);
	data.set_method(method);

	*addr = _next_addr();
	_sessions.insert(std::make_pair(addr->u64, resp));

	tll_msg_t msg = {};
	msg.type = TLL_MESSAGE_CONTROL;
	msg.msgid = data.meta_id();
	msg.addr = *addr;
	msg.data = buf.data();
	msg.size = buf.size();
	this->_callback(&msg);
	return 0;
}

template <typename T, typename R>
int WSNode<T, R>::_disconnected(R * resp, tll_addr_t addr)
{
	if (this->state() != tll::state::Closing) {
		auto it = _sessions.find(addr.u64);
		if (it != _sessions.end())
			_sessions.erase(it);
	}

	std::vector<char> buf;
	auto data = ws_scheme::Disconnect::bind(buf);
	buf.resize(data.meta_size());

	tll_msg_t msg = {};
	msg.type = TLL_MESSAGE_CONTROL;
	msg.addr = addr;
	msg.msgid = data.meta_id();
	msg.data = buf.data();
	msg.size = buf.size();
	this->_callback(&msg);

	//user->pending = {};

	if (resp)
		resp->close();
	return 0;
}

template <Method M>
void WSServer::_http(uWS::HttpResponse<false> * resp, uWS::HttpRequest *req)
{
	auto uri = req->getUrl();
	_log.debug("Requested {}", uri);
	auto node = node_lookup(uri);
	if (!node) {
		_log.debug("Requested url not found: '{}'", uri);
		resp->writeStatus("404 Not Found");
		return resp->end("Requested url not found");
	}

	if (std::holds_alternative<WSWS *>(*node)) {
		_log.debug("HTTP request to WS endpoint {}", uri);
		resp->writeStatus("400 Bad Request");
		return resp->end("WebSocket node");
	}

	auto channel = std::get<WSHTTP *>(*node);
	tll_addr_t addr = {};
	channel->_connected(resp, req->getFullUrl(), &addr, M);

	auto h = req->getHeader("content-length");
	if (h.size()) {
		_log.debug("Content-Length: {}", h);
	}

	resp->onAborted([channel, addr]() { channel->_disconnected(nullptr, addr); });
	resp->onData([channel, addr](std::string_view data, bool last) {
		if (data.size() == 0 && !last)
			return;
		tll_msg_t msg = {};
		msg.type = TLL_MESSAGE_DATA;
		msg.addr = addr;
		msg.data = data.data();
		msg.size = data.size();
		channel->_callback_data(&msg);
	});
}

void WSServer::_ws_upgrade(uWS::HttpResponse<false> * resp, uWS::HttpRequest *req, us_socket_context_t *context)
{
	auto uri = req->getUrl();
	_log.debug("Requested {}", uri);
	auto node = node_lookup(uri);
	if (!node) {
		_log.debug("Requested url not found: '{}'", uri);
		resp->writeStatus("404 Not Found");
		return resp->end("Requested url not found");
	}

	std::variant<WSWS *, WSPub *> channel;

	auto fd = (int) (uintptr_t) resp->getNativeHandle();
	if (_sndbuf && tll::network::setsockoptT<int>(fd, SOL_SOCKET, SO_SNDBUF, _sndbuf))
		this->_log.warning("Failed to set sndbuf to {}: {}", _sndbuf, strerror(errno));

	if (_rcvbuf && tll::network::setsockoptT<int>(fd, SOL_SOCKET, SO_RCVBUF, _rcvbuf))
		this->_log.warning("Failed to set rcvbuf to {}: {}", _rcvbuf, strerror(errno));

	if (std::holds_alternative<WSHTTP *>(*node)) {
		_log.debug("WS request to HTTP endpoint {}", uri);
		resp->writeStatus("400 Bad Request");
		return resp->end("HTTP node");
	} else if (std::holds_alternative<WSWS *>(*node)) {
		channel = std::get<WSWS *>(*node);
	} else if (std::holds_alternative<WSPub *>(*node)) {
		channel = std::get<WSPub *>(*node);
	}

	resp->template upgrade<User>({ channel }
		, req->getHeader("sec-websocket-key")
		, req->getHeader("sec-websocket-protocol")
		, req->getHeader("sec-websocket-extensions")
		, context
		);
}

void WSServer::_ws_open(WebSocket *ws)
{
	auto user = ws->getUserData();
	std::visit([&ws, &user](auto && c) { c->_connected(ws, "", &user->addr); }, user->channel);
}

void WSServer::_ws_message(WebSocket *ws, std::string_view message, uWS::OpCode)
{
	auto user = ws->getUserData();

	if (!std::holds_alternative<WSWS *>(user->channel))
		return;
	tll_msg_t msg = {};
	msg.type = TLL_MESSAGE_DATA;
	msg.addr = user->addr;
	msg.data = message.data();
	msg.size = message.size();
	std::get<WSWS *>(user->channel)->_callback_data(&msg);
}

void WSServer::_ws_drain(WebSocket *ws)
{
	auto user = ws->getUserData();

	if (std::holds_alternative<WSPub *>(user->channel))
		return std::get<WSPub *>(user->channel)->writeable(ws, user);
}

void WSServer::_ws_close(WebSocket *ws, int code, std::string_view message)
{
	auto user = ws->getUserData();
	std::visit([&user](auto && c) { c->_disconnected(nullptr, user->addr); }, user->channel);
}

TLL_DEFINE_IMPL(WSServer);
TLL_DEFINE_IMPL(WSHTTP);
TLL_DEFINE_IMPL(WSWS);
TLL_DEFINE_IMPL(WSPub);

TLL_DEFINE_MODULE(WSServer, WSHTTP, WSWS, WSPub);
