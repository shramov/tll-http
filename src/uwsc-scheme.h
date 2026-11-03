#pragma once

#include <tll/scheme/binder.h>
#include <tll/util/conv.h>

namespace uwsc_scheme {

static constexpr std::string_view scheme_string = R"(yamls+gz://eJxNjsEKwjAQRO/5ir3txUBVEMxZz/YPJCSpBtokdBNESv/drFjMbWfeDDsSgp6cAkQBEFP2MZCCBU1KkgklbRxWXl5k7mSebnK4CrnVeh8eXPVWwbmx49/ed/UYvBstqXoBSFh+sTln3EF+JxbFh3w8VN3MmB3FsbDkDYEqRY6zsmXWX7I2e67B3oaLznr7furEB5XnRBQ=)";

struct Ping
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "Ping"; }
	static constexpr int meta_id() { return 9; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Ping::meta_size(); }
		static constexpr auto meta_name() { return Ping::meta_name(); }
		static constexpr auto meta_id() { return Ping::meta_id(); }
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

struct Pong
{
	static constexpr size_t meta_size() { return 4; }
	static constexpr std::string_view meta_name() { return "Pong"; }
	static constexpr int meta_id() { return 10; }
	static constexpr size_t offset_rtt = 0;

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Pong::meta_size(); }
		static constexpr auto meta_name() { return Pong::meta_name(); }
		static constexpr auto meta_id() { return Pong::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		template <typename RBuf>
		void copy(const binder_type<RBuf> &rhs)
		{
			set_rtt(rhs.get_rtt());
		}

		using type_rtt = std::chrono::duration<uint32_t, std::nano>;
		type_rtt get_rtt() const { return this->template _get_scalar<type_rtt>(offset_rtt); }
		void set_rtt(type_rtt v) { return this->template _set_scalar<type_rtt>(offset_rtt, v); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct EndOfData
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "EndOfData"; }
	static constexpr int meta_id() { return 60; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return EndOfData::meta_size(); }
		static constexpr auto meta_name() { return EndOfData::meta_name(); }
		static constexpr auto meta_id() { return EndOfData::meta_id(); }
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

} // namespace uwsc_scheme
