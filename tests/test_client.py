#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import decorator
import os
import pytest

from tll import asynctll
from tll.channel import Context
from tll.test_util import ports

@pytest.fixture
def context():
    ctx = Context()
    try:
        ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-uws"))
        ctx.load(os.path.join(os.environ.get("BUILD_DIR", "build"), "tll-uwsc"))
    except:
        pytest.skip("uws:// or ws:// channels not available")
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
