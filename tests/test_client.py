#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import asyncio
import decorator
import os
import pytest
import websockets

from tll.asynctll import asyncio as asynctll
from tll.channel import Context
from tll.test_util import ports

@pytest.fixture(params=['uwsc', 'wslay'])
def context(request) -> Context:
    ctx = Context()
    try:
        ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-uws"))
        ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), f"tll-{request.param}"))
    except:
        pytest.skip(f"uws:// or {request.param} channels not available")
    return ctx

@pytest.fixture
def server(asyncloop, port):
    c = asyncloop.Channel(f'uws://*:{port}', name='server')
    yield c
    c.close()

@pytest.fixture
def asyncloop(context):
    loop = asynctll.Loop(context)
    yield loop
    loop.destroy()
    loop = None

@pytest.fixture
def port():
    return ports.TCP4

@decorator.decorator
def asyncloop_run(f, asyncloop, *a, **kw):
    asyncloop.run(f(asyncloop, *a, **kw))

@pytest.fixture(scope='function', params=['yes', 'no'])
def client(asyncloop, port, request):
    c = asyncloop.Channel(f'ws://127.0.0.1:{port}/path', binary=request.param, name='client', dump='yes', **{'header.X-A': 'a', 'header.X-B': 'b'})
    yield c
    c.close()
    del c

@asyncloop_run
async def test(asyncloop, server, client, port):
    sub = asyncloop.Channel("uws+ws://path", master=server, name='server/ws', dump='yes');

    server.open()
    client.open(**{'header.X-A': 'zzz'})

    assert await client.recv_state() == client.State.Error

    client.close()
    sub.open()
    client.open(**{'header.X-A': 'Aa'})

    assert await client.recv_state() == client.State.Active
    assert client.state == client.State.Active

    assert client.config['info.local.af'] == 'ipv4'
    assert client.config['info.local.host'] == '127.0.0.1'
    assert client.config['info.remote.af'] == 'ipv4'
    assert client.config['info.remote.host'] == '127.0.0.1'
    assert client.config['info.remote.port'] == f'{port}'

    m = await sub.recv(0.1)
    assert m.type == m.Type.Control
    m = sub.unpack(m)
    assert m.SCHEME.name == 'Connect'
    assert m.path == '/path'
    headers = {h.header: h.value for h in m.headers if h.header}
    assert {k: v for k, v in headers.items() if k not in ('host', 'sec-websocket-key')} == {
            'connection': 'Upgrade',
            'sec-websocket-version': '13',
            'upgrade': 'websocket',
            'x-a': 'Aa',
            'x-b': 'b',
            }

    client.post(b'xxx')
    client.post(b'yyy')

    m = await sub.recv(0.1)
    assert m.type == m.Type.Data
    assert m.data.tobytes() == b'xxx'

    m = await sub.recv(0.1)
    assert m.type == m.Type.Data
    assert m.data.tobytes() == b'yyy'

    sub.post(b'zzz', addr=m.addr)

    m = await client.recv(0.1)
    assert m.type == m.Type.Data
    assert m.data.tobytes() == b'zzz'

    client.close()

    m = await sub.recv(0.1)
    assert m.type == m.Type.Control
    m = sub.unpack(m)
    assert m.SCHEME.name == 'Disconnect'

@asyncloop_run
async def test_server_write_full(asyncloop, port):
    server = asyncloop.Channel(f'uws://*:{port}', name='server', sndbuf='16kb')
    client = asyncloop.Channel(f'ws://127.0.0.1:{port}/path', name='client', dump='frame')
    sub = asyncloop.Channel("uws+ws://path", master=server, name='server/path', dump='frame');

    server.open()
    sub.open()
    client.open()

    m = await sub.recv()

    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['Connect'].msgid)
    addr = m.addr

    for i in range(100):
        sub.post(b'x' * 16 * 1024, addr=addr, seq=i)
        if sub.result:
            break

    m = await sub.recv(0.001)
    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['WriteFull'].msgid)
    assert m.addr == addr

    client.resume()
    for _ in range(i):
        m = await client.recv()
        assert len(m.data) == 16 * 1024

    m = await sub.recv(0.001)
    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['WriteReady'].msgid)
    assert m.addr == addr

@asyncloop_run
async def test_open_path(asyncloop, port):
    server = asyncloop.Channel(f'uws://*:{port}', name='server', sndbuf='16kb')
    client = asyncloop.Channel(f'ws://127.0.0.1:{port}', name='client', dump='frame')
    sub = asyncloop.Channel("uws+ws://path", master=server, name='server/path', dump='frame');

    server.open()
    sub.open()
    client.open(path='/path')

    m = await sub.recv()
    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['Connect'].msgid)

    client.close()

    m = await sub.recv()
    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['Disconnect'].msgid)

    client.open()
    assert (await client.recv_state()) == client.State.Error

@asyncloop_run
async def test_ping_interval(asyncloop, port):
    if not asyncloop.context.has_impl("wslay+"):
        pytest.skip("uwsc ping interval is too large")
    server = asyncloop.Channel(f'uws://*:{port}', name='server')
    client = asyncloop.Channel(f'ws://127.0.0.1:{port}/path;report-ping=yes;ping=1ms', name='client', dump='yes')
    sub = asyncloop.Channel("uws+ws://path", master=server, name='server/path', dump='frame');

    server.open()
    sub.open()
    client.open()

    m = await sub.recv()
    assert (m.type, m.msgid) == (m.Type.Control, sub.scheme_control['Connect'].msgid)

    m = await client.recv(0.1)
    assert (m.type, m.msgid) == (m.Type.Control, client.scheme_control['Pong'].msgid)

class Echo:
    def __init__(self, count: int = 1):
        self.count = count
        self.headers = {}
        self.request = asyncio.get_running_loop().create_future()

    async def __call__(self, sock):
        self.request.set_result(getattr(sock, 'request', None))
        async for message in sock:
            for _ in range(self.count):
                await sock.send(message)

@asyncloop_run
async def test_python(asyncloop, wsserve, client, port):
    echo = Echo()
    async with wsserve(echo, '*', port):
        try:
            client.open(**{'header.X-A': 'Aa'})

            assert await client.recv_state() == client.State.Active
            assert client.state == client.State.Active

            client.post(b'xxx')
            client.post(b'yyy')

            req = await asyncio.wait_for(echo.request, 0.1)
            if req is not None:
                assert req.path == '/path'
                assert {k: v for k, v in req.headers.items() if k not in ('host', 'sec-websocket-key')} == {
                        'connection': 'Upgrade',
                        'sec-websocket-version': '13',
                        'upgrade': 'websocket',
                        'x-a': 'Aa',
                        'x-b': 'b',
                        }
            else:
                # Request appeared somewhere between major versions 10 and 15
                assert int(websockets.version.version.split('.', 1)[0]) < 15

            m = await client.recv(0.1)
            assert m.data.tobytes() == b'xxx'

            m = await client.recv(0.1)
            assert m.data.tobytes() == b'yyy'
        finally:
            client.close()

@asyncloop_run
async def test_eod(asyncloop, wsserve, port):
    if not asyncloop.context.has_impl("wslay+"):
        pytest.skip("uwsc does not support EndOfData")

    client = asyncloop.Channel(f'ws://127.0.0.1:{port}/path;end-of-data=yes', name='client', dump='yes')

    echo = Echo(count=5)
    async with wsserve(echo, '*', port):
        try:
            client.open()

            assert await client.recv_state() == client.State.Active
            assert client.state == client.State.Active

            req = await asyncio.wait_for(echo.request, 0.1)

            for body in [b'xxx', b'yyy']:
                client.post(body)

                for _ in range(echo.count):
                    m = await client.recv(0.1)
                    assert m.data.tobytes() == body

                m = await client.recv(0.1)

                assert (m.type, m.msgid) == (m.Type.Control, client.scheme_control['EndOfData'].msgid)
        finally:
            client.close()
