HTTP Channels for TLL framework
===============================

HTTP and WebSocket client and server channels for TLL_:

 - HTTP/FTP/... client based on cURL_ shipped in ``tll-curl`` module, see ``doc/curl.rst``.

 - WebSocket client based on forked libuwsc_ shipped in ``tll-uwsc`` module, see ``doc/ws.rst``

 - HTTP and WebSocket server based on uWebSockets_ shipped in ``tll-uws`` module, see
   ``doc/uws.rst``

Compilation
-----------

.. note::
  Prebuilt package ``libtll-http`` can be installed from repostory ``https://psha.org.ru/debian``.

Module depends on TLL_, fmtlib (``libfmt-dev``), cURL_
(``libcurl4-openssl-dev``), ``libev-dev``, ``libuv1-dev``, ``libssl-dev`` and
uses meson_ build system (on non-Debian systems names can differ). uWebSockets_
and libuwsc_ (forked version) libraries are included as git submodules.
Compilation is straightforward::

  meson setup build
  ninja -vC build

.. _TLL: https://github.com/shramov/tll/
.. _cURL: https://curl.se/
.. _libuwsc: https://github.com/zhaojh329/libuwsc
.. _meson: https://mesonbuild.com/ 
.. _uWebSockets: https://github.com/uNetworking/uWebSockets

..
  vim: sts=2 sw=2 et tw=100
