tll-http
========

:Manual Section: 7
:Manual Group: TLL
:Subtitle: HTTP related channels

Synopsis
--------

``curl+http://HOST:PORT/PATH;...``

``ws://HOST:PORT/PATH;...``

``uws://HOST:PORT``

``uws+http://PATH``

``uws+ws://PATH``


Description
-----------

Following types of channels are implemented for TLL:

 - HTTP/FTP/... client based on cURL shipped in ``tll-curl`` module, see ``tll-channel-curl(7)``

 - WebSocket client based on libuwsc shipped in ``tll-uwsc`` module, see ``tll-channel-ws(7)``

 - HTTP and WebSocket server based on uWebSockets shipped in ``tll-uws`` module, see
   ``tll-channel-uws(7)``

See also
--------

``tll-channel-curl(7)``, ``tll-channel-ws(7)``, ``tll-channel-uws(7)``

..
    vim: sts=4 sw=4 et tw=100
