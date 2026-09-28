#!/usr/bin/env python
# vim: sts=4 sw=4 et

import pytest
import websockets

import tll.logger

tll.logger.init()

@pytest.fixture
def wsserve():
    if int(websockets.version.version.split('.')[0]) < 10:
        pytest.skip(f"Websockets module version too old: {websockets.version.version}, need at least 10.0")
    return websockets.serve
