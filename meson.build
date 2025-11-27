project('tll-ws', 'c', 'cpp', version: '0.2.0', default_options: ['cpp_std=c++17', 'c_std=c11', 'werror=true', 'optimization=2', 'b_lto=true'])

cc = meson.get_compiler('c')
if cc.get_id() == 'gcc' and cc.version().version_compare('< 8.0')
        add_project_arguments('-Wno-unused-variable', language: 'cpp')
endif

include = [include_directories('src')]

tll = dependency('tll')
fmt = dependency('fmt')
curl = dependency('libcurl') #, version: '>=7.63', required: false, disabler: true)
libuv = dependency('libuv')

lws = dependency('libwebsockets', required: get_option('with_lws'), disabler: true)
libev = meson.get_compiler('c').find_library('ev', required: get_option('with_lws'), disabler: true)
rst2man = find_program('rst2man', disabler: true, required: false)

lib = shared_library('tll-ws',
		['src/channel.cc', 'src/names.cc', 'src/ev-backend.c'],
		include_directories : include,
		dependencies : [fmt, lws, tll, libev],
		install : true
)

subdir('third_party')

uws = shared_library('tll-uws',
		['src/uws.cc', 'src/uws-epoll.c'],
		include_directories : include,
		dependencies : [fmt, tll, libuv, uwebsockets, usockets],
		install : true
)

uwsc = shared_library('tll-uwsc',
		['src/uwsc.cc', 'src/ev-backend.c'],
		include_directories : include,
		dependencies : [fmt, tll, libuwsc, libev],
		install : true
)

curl = shared_library('tll-curl',
		['src/curl.cc'],
		include_directories : include,
		dependencies : [fmt, tll, curl],
		install : true
)

executable('bench-getrandom', 'bench/random.cc', dependencies: [fmt, tll, openssl])

install_data(['src/http.yaml', 'src/ws.yaml'], install_dir: get_option('datadir') / 'tll/scheme/tll/')

test('pytest', import('python').find_installation('python3')
	, args: ['-m', 'pytest', '-v', 'tests']
	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
	, workdir: meson.current_source_dir()
)

foreach f : ['ws.rst', 'curl.rst', 'uws.rst']
	custom_target('channel-man-@0@'.format(f)
		, input: 'doc' / f
		, output : 'tll-channel-@BASENAME@.7'
		, command : [rst2man, '@INPUT@', '@OUTPUT@']
		, install_dir: get_option('mandir') / 'man7'
		, install: true
	)
endforeach

custom_target('man-http'
        , input: 'doc/http.rst'
        , output : 'tll-http.7'
        , command : [rst2man, '@INPUT@', '@OUTPUT@']
        , install_dir: get_option('mandir') / 'man7'
        , install: true
)
