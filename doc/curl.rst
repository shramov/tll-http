tll-channel-curl
================

:Manual Section: 7
:Manual Group: TLL
:Subtitle: HTTP/FTP/etc client channel based on cURL

Synopsis
--------

``curl+PROTO://URL;transfer={single|data|control};method=<METHOD>;header.A=B;header.C=D;...``

or

::

  curl://;name=multi-master
  curl+PROTO://URL;master=multi-master

Description
-----------

Channel implements HTTP (but not limited to HTTP) client based on libcurl. It can work either in
single-request mode, when channel becomes inactive after finishing transfer, or in multi-request
mode.

Channel implementation is shipped in ``tll-curl`` module.

Init parameters
~~~~~~~~~~~~~~~

All parameters may be specified with ``curl.`` prefix.

``transfer={single|data|control}`` (default ``single``) - select channel working mode:

  - ``single`` -  perform only one request

  - ``data`` - start new request with same parameters each time data is posted into the channel.
    Requests are identified by ``addr`` field in the message. Received data is produced with same
    address as initial message.

  - ``control`` - same as ``data`` mode but start new request with ``Connect`` control message that
    holds additional connection parameters

``autoclose=<bool>``, default ``false`` - close after request is finished, only for ``single``
transfer mode

``method={GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH}``, default ``GET`` - specify http
method to use in single mode or default one for data/control modes.

``recv-size=<size>`` (default ``64kb``) - buffer size that accumulates received data. Each time it
is flled channel produces new message.

``recv-chunked=<bool>`` (default ``false``) - produce incoming messages as
chunks of data are received. If disabled - accumulate data (up to ``recv-size``)
and produce only one message.

``expect-timeout=<duration>`` (default ``1s``) - timeout to wait for ``100 Continue`` reply from the
server when sending data. Not needed for requests without body.

``header.**=<string>`` - list of additional HTTP headers passed to cURL using
``CURLOPT_HTTPHEADER``, not applicable to other protocols.

Control messages
----------------

Each request produces two control messages: ``Connect`` when server responds to request (may contain
error code, for example ``404`` or ``500``) and ``Disconnect`` when request is finished. If request
can not be performed only ``Disconnect`` is generated with non-empty ``code`` and ``error`` fields.

In ``control`` mode ``Connect`` message is used to create new request with following parameters:

 - ``method``: if not ``UNDEFINED`` - override ``method`` channel parameter.
 - ``path``: append to ``protocol://host/`` from channel init parameters
 - ``size``: size of request body, if set to 0 then no body is expected.
 - ``headers``: list of additional headers, overrides values with same name from ``header.**`` init
   parameter.
 - ``code``: ignored when new request is created, filled with value reported by server.

Control scheme:

.. code-block:: yaml

  - name: Header
    fields:
      - {name: header, type: string}
      - {name: value, type: string}

  - name: Connect
    enums:
      Method: {type: int8, enum: {UNDEFINED: 0, GET: 1, HEAD: 2, POST: 3, PUT: 4, DELETE: 5, CONNECT: 6, OPTIONS: 7, TRACE: 8, PATCH: 9}}
    fields:
      - {name: method, type: Method}
      - {name: code, type: int16}
      - {name: size, type: int64}
      - {name: path, type: string}
      - {name: headers, type: '*Header'}

  - name: Disconnect
    fields:
      - {name: code, type: int16}
      - {name: error, type: string}

Examples
--------

Retreive data from HTTP server with extra headers and close afterwards

::

  curl+http://example.com/file.dat;header.X-Header-0=A;header.X-Header-1=B;autoclose=yes

Create one GET and one POST channel sharing single cURL multi handle that can keep connection to the
server between requests. Posting data message into ``http-get`` and ``http-post`` channels starts
new request to either ``/get`` or ``/post`` url::

  curl://;name=multi
  curl+http://example.com/get;master=multi;name=http-get;transfer=data
  curl+http://example.com/post;master=multi;name=http-post;transfer=data;method=POST


Create one channel and perform several POSTs to different paths, send 10 bytes to ``/a`` and 20 to
``/b``:

.. code:: python

   c = loop.Channel('curl+http://example.com;method=POST;name=client')
   c.open()
   c.post({'path': '/a', 'size': 10}, name='Connect', type=c.Type.Control, addr=1)
   c.post({'path': '/b', 'size': 20}, name='Connect', type=c.Type.Control, addr=2)
   c.post(b'x' * 10, addr=1)
   c.post(b'y' * 20, addr=2)
   m = await c.recv()
   if m.addr == 1:
     print("Reply from /a")
   else:
     print("Reply from /b")

See also
--------

``tll-channel-common(7)``, ``curl(1)``

..
    vim: sts=4 sw=4 et tw=100

