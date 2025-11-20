libuv = dependency('libuv')
zlib = dependency('zlib')
openssl = dependency('openssl')

usockets_src = files(
	'usockets/src/bsd.c',
	'usockets/src/context.c',
	'usockets/src/eventing/epoll_kqueue.c',
	#'usockets/src/eventing/libuv.c',
	'usockets/src/socket.c',
	'usockets/src/loop.c',
)

no_use_after_free_args = []
if cc.get_id() == 'gcc'
  no_use_after_free_args = ['-Wno-use-after-free']
endif

usockets_include = include_directories('usockets/src')
usockets_lib = static_library('usockets',
		usockets_src,
		c_args : ['-DLIBUS_NO_SSL', '-DLIBUS_USE_EPOLL'] + no_use_after_free_args,
		include_directories : usockets_include,
		install : false
)

usockets = declare_dependency(include_directories: usockets_include, link_with: usockets_lib, dependencies: [libuv, zlib])
uwebsockets = declare_dependency(include_directories: include_directories('uwebsockets/src'), dependencies: [usockets])
echo_server = executable('ws-echo-server', 'uwebsockets/examples/EchoServer.cpp', dependencies: [uwebsockets])

libuwsc_src = files(
	'libuwsc/src/sha1.c',
	'libuwsc/src/utils.c',
	'libuwsc/src/uwsc.c',
	'uwsc/buffer/buffer.c',
	'uwsc/ssl/openssl.c',
	'uwsc/log.cc',
)
libuwsc_include = include_directories('libuwsc/src', 'uwsc/buffer', 'uwsc')

libuwsc_lib = static_library('uwsc',
	libuwsc_src,
	include_directories: libuwsc_include,
	c_args: ['-D_GNU_SOURCE', '-Wno-strict-aliasing'],
	dependencies: [libev, openssl, tll],
	install: false
)
libuwsc = declare_dependency(include_directories: libuwsc_include, link_with: libuwsc_lib, dependencies: [libev, openssl, tll])
