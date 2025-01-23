tll-channel-ws
==============

:Manual Section: 7
:Manual Group: TLL
:Subtitle: Websocket client channel

Synopsis
--------

``uws://HOST:PORT``

and

``uws+http://PATH``

``uws+ws://PATH``


Description
-----------

Channel implements Websocket and HTTP server using uWebSockets library. ``uws://host:port`` creates
server object and ``uws+http://path;master=server`` and ``uws+ws://path;master=server`` objects add
endpoints into it. Master object does not emit any messages, everything is passed through endpoints.

Channel implementation is shipped in ``tll-uws`` module.

Master init parameters
~~~~~~~~~~~~~~~~~~~~~~

``HOST:PORT`` - host and port to listen for incoming connections.

``binary=<bool>`` (default ``yes``) - send data as binary frames or as text

``max-payload-size=<size>`` (default ``16kb``) - maximum allowed payload size from client


Endpoint init parameters
~~~~~~~~~~~~~~~~~~~~~~~~

``PATH`` - path prefix for endpoint

Control messages
----------------

Channel emits two types of control messages: ``Connect`` for new client and ``Disconnect`` when
request is finished (or websocket connection is terminated). Also ``Disconnect`` can be posted to
drop client. All data messages from same connection have same ``addr`` field as in ``Connect`` and
``Disconnect`` messages.

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

Create server and server HTTP requests on ``http://host:8080/http-path`` and websocket requests
on ``http://host:8080/ws-path``::

    uws://*:8080;name=server
    uws+http://http-path;name=http
    uws+ws://ws-path;name=ws

See also
--------

``tll-channel-common(7)``

..
    vim: sts=4 sw=4 et tw=100
