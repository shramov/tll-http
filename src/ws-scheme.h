#pragma once

#include <tll/scheme/binder.h>
#include <tll/util/conv.h>

namespace ws_scheme {

static constexpr std::string_view scheme_string = R"(yamls+gz://eJyNUE1vgkAUvPsr9rZJIwkqtdWbgbWYtGAU02ND4LVsAgth1zaW8N/7VsD6mfY2b2cyszMGEWEGU0Jpj5C8UDwXckoqGhWFoRlZhBFQ5L/km4wSyIDWqASxzeQUASH0BVSSx6ip1K5AKy7UY3+v0Ea273nMDpAe9wl12DMLGB73eDwx/TxA5LKZg3CI0F8GC99b4/WA13IW2C7iicb+WutHGm40shAFq5mt/TCRbjyHzRce01ZmXfeMrpsLYQylbvjOIY3bjxukavmk4fukKUClKrn42Bc9ln2G6RauqA45di4EREoH8Rib3QzMmskOVu2E54FRHh/l4a6D8YVG8u9Tzdi60BShSv5s14wgf3V37WxHBR0uo9OOw5sd//N5KMv82u6HwNeSK5hv07TLG5ln5Ao/uetYy+z9AGxbzAM=)";

enum class Method: int8_t
{
	UNDEFINED = 0,
	GET = 1,
	HEAD = 2,
	POST = 3,
	PUT = 4,
	DELETE = 5,
	CONNECT = 6,
	OPTIONS = 7,
	TRACE = 8,
	PATCH = 9,
};

struct Header
{
	static constexpr size_t meta_size() { return 16; }
	static constexpr std::string_view meta_name() { return "Header"; }
	static constexpr size_t offset_header = 0;
	static constexpr size_t offset_value = 8;

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Header::meta_size(); }
		static constexpr auto meta_name() { return Header::meta_name(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
			set_header(rhs.get_header());
			set_value(rhs.get_value());
		}

		std::string_view get_header() const { return this->template _get_string<tll_scheme_offset_ptr_t>(offset_header); }
		void set_header(std::string_view v) { return this->template _set_string<tll_scheme_offset_ptr_t>(offset_header, v); }

		std::string_view get_value() const { return this->template _get_string<tll_scheme_offset_ptr_t>(offset_value); }
		void set_value(std::string_view v) { return this->template _set_string<tll_scheme_offset_ptr_t>(offset_value, v); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct Connect
{
	static constexpr size_t meta_size() { return 27; }
	static constexpr std::string_view meta_name() { return "Connect"; }
	static constexpr int meta_id() { return 1; }
	static constexpr size_t offset_method = 0;
	static constexpr size_t offset_code = 1;
	static constexpr size_t offset_size = 3;
	static constexpr size_t offset_path = 11;
	static constexpr size_t offset_headers = 19;

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Connect::meta_size(); }
		static constexpr auto meta_name() { return Connect::meta_name(); }
		static constexpr auto meta_id() { return Connect::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
			set_method(rhs.get_method());
			set_code(rhs.get_code());
			set_size(rhs.get_size());
			set_path(rhs.get_path());
			get_headers().copy(rhs.get_headers());
		}

		using type_method = Method;
		type_method get_method() const { return this->template _get_scalar<type_method>(offset_method); }
		void set_method(type_method v) { return this->template _set_scalar<type_method>(offset_method, v); }

		using type_code = int16_t;
		type_code get_code() const { return this->template _get_scalar<type_code>(offset_code); }
		void set_code(type_code v) { return this->template _set_scalar<type_code>(offset_code, v); }

		using type_size = int64_t;
		type_size get_size() const { return this->template _get_scalar<type_size>(offset_size); }
		void set_size(type_size v) { return this->template _set_scalar<type_size>(offset_size, v); }

		std::string_view get_path() const { return this->template _get_string<tll_scheme_offset_ptr_t>(offset_path); }
		void set_path(std::string_view v) { return this->template _set_string<tll_scheme_offset_ptr_t>(offset_path, v); }

		using type_headers = tll::scheme::binder::List<Buf, Header::binder_type<Buf>, tll_scheme_offset_ptr_t>;
		using const_type_headers = tll::scheme::binder::List<const Buf, Header::binder_type<const Buf>, tll_scheme_offset_ptr_t>;
		const_type_headers get_headers() const { return this->template _get_binder<const_type_headers>(offset_headers); }
		type_headers get_headers() { return this->template _get_binder<type_headers>(offset_headers); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct Disconnect
{
	static constexpr size_t meta_size() { return 10; }
	static constexpr std::string_view meta_name() { return "Disconnect"; }
	static constexpr int meta_id() { return 2; }
	static constexpr size_t offset_code = 0;
	static constexpr size_t offset_error = 2;

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Disconnect::meta_size(); }
		static constexpr auto meta_name() { return Disconnect::meta_name(); }
		static constexpr auto meta_id() { return Disconnect::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
			set_code(rhs.get_code());
			set_error(rhs.get_error());
		}

		using type_code = int16_t;
		type_code get_code() const { return this->template _get_scalar<type_code>(offset_code); }
		void set_code(type_code v) { return this->template _set_scalar<type_code>(offset_code, v); }

		std::string_view get_error() const { return this->template _get_string<tll_scheme_offset_ptr_t>(offset_error); }
		void set_error(std::string_view v) { return this->template _set_string<tll_scheme_offset_ptr_t>(offset_error, v); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct WriteFull
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "WriteFull"; }
	static constexpr int meta_id() { return 30; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return WriteFull::meta_size(); }
		static constexpr auto meta_name() { return WriteFull::meta_name(); }
		static constexpr auto meta_id() { return WriteFull::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
		}
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct WriteReady
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "WriteReady"; }
	static constexpr int meta_id() { return 40; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return WriteReady::meta_size(); }
		static constexpr auto meta_name() { return WriteReady::meta_name(); }
		static constexpr auto meta_id() { return WriteReady::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
		}
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

} // namespace ws_scheme

template <>
struct tll::conv::dump<ws_scheme::Method> : public to_string_from_string_buf<ws_scheme::Method>
{
	template <typename Buf>
	static inline std::string_view to_string_buf(const ws_scheme::Method &v, Buf &buf)
	{
		switch (v) {
		case ws_scheme::Method::CONNECT: return "CONNECT";
		case ws_scheme::Method::DELETE: return "DELETE";
		case ws_scheme::Method::GET: return "GET";
		case ws_scheme::Method::HEAD: return "HEAD";
		case ws_scheme::Method::OPTIONS: return "OPTIONS";
		case ws_scheme::Method::PATCH: return "PATCH";
		case ws_scheme::Method::POST: return "POST";
		case ws_scheme::Method::PUT: return "PUT";
		case ws_scheme::Method::TRACE: return "TRACE";
		case ws_scheme::Method::UNDEFINED: return "UNDEFINED";
		default: break;
		}
		return tll::conv::to_string_buf<int8_t, Buf>((int8_t) v, buf);
	}
};
