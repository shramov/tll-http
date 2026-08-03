#ifndef _SRC_HTTP_H
#define _SRC_HTTP_H

#include <cstring>
#include <string_view>

#include <tll/compat/expected.h>
#include <tll/util/memoryview.h>

namespace tll::http {

inline bool svcasecmp(std::string_view l, std::string_view r)
{
	if (l.size() != r.size())
		return false;
	return strncasecmp(l.data(), r.data(), l.size()) == 0;
}

struct Reply
{
	enum Version { Invalid = 0, HTTP_1_0 = 10, HTTP_1_1 = 11 } version = Invalid;
	std::string_view code;
	std::string_view code_string;
	std::string_view body;
	using Callback = int (*)(std::string_view header, std::string_view value);

	template <typename F>
	static tll::compat::expected<Reply, std::string_view> parse(std::string_view buf, F &cb)
	{
		using namespace std::string_view_literals;
		Reply r = {};
		auto sep = buf.find("\r\n");
		if (sep == buf.npos)
			return tll::compat::unexpected{"No \\r\\n found"sv};
		auto line = buf.substr(0, sep);
		buf = buf.substr(sep + 2);
		if (line.substr(0, 5) != "HTTP/")
			return tll::compat::unexpected{"No HTTP/ prefix"sv};
		line = line.substr(5);
		sep = line.find(' ');
		if (sep == line.npos)
			return tll::compat::unexpected{"No space in first line"sv};
		{
			auto version = line.substr(0, sep);
			line = line.substr(sep + 1);
			if (version == "1.0")
				r.version = HTTP_1_0;
			else if (version == "1.1")
				r.version = HTTP_1_1;
			else
				return tll::compat::unexpected{"Unsupported protocol version"sv};
		}

		sep = line.find(' ');
		if (sep != line.npos) {
			r.code = line.substr(0, sep);
			r.code_string = line.substr(sep + 1);
		} else
			r.code = line;

		while (true) {
			sep = buf.find("\r\n");
			if (sep == buf.npos)
				return tll::compat::unexpected{"Truncated response"sv};
			line = buf.substr(0, sep);
			buf = buf.substr(sep + 2);
			if (line.empty())
				break;
			sep = line.find(": ");
			if (sep == line.npos)
				return tll::compat::unexpected{"No ':' separator in header"sv};
			auto header = line.substr(0, sep);
			auto value = line.substr(sep + 2);
			if (cb(header, value) != 0)
				return tll::compat::unexpected{"Error in header callback"sv};
		}

		r.body = buf;
		return r;
	}
};

} // namespace tll::http

#endif//_SRC_HTTP_H
