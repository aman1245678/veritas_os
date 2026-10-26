"""Mounted WebSocket disconnects must release idle subscriptions promptly."""

import asyncio
import os

import pytest

from veritas_os.api import server
from veritas_os.api.sse_hub import SSEEventHub


@pytest.mark.parametrize("publish_event", [False, True])
@pytest.mark.parametrize("termination", ["disconnect", "cancel", "send_error"])
async def test_mounted_websocket_disconnect_releases_subscription(
    monkeypatch, publish_event, termination,
):
    monkeypatch.setenv("VERITAS_ENV", "production")
    monkeypatch.delenv("VERITAS_POSTURE", raising=False)
    monkeypatch.setenv("VERITAS_API_KEY", "websocket-disconnect-test")
    monkeypatch.delenv("VERITAS_API_KEYS", raising=False)
    monkeypatch.setattr(server.app.state, "security_startup_complete", True, raising=False)
    monkeypatch.setattr(server.app.state, "security_startup_pid", os.getpid(), raising=False)
    hub = SSEEventHub(timestamp_factory=lambda: "test")
    monkeypatch.setattr(server, "_event_hub", hub)
    incoming = asyncio.Queue()
    accepted = asyncio.Event()
    delivered = asyncio.Event()
    fail_send = False

    async def send(message):
        if message["type"] == "websocket.accept":
            accepted.set()
        if message["type"] == "websocket.send":
            if fail_send:
                raise RuntimeError("synthetic send failure")
            delivered.set()

    scope = {
        "type": "websocket", "asgi": {"version": "3.0"},
        "scheme": "ws", "path": "/v1/ws/trustlog", "raw_path": b"/v1/ws/trustlog",
        "query_string": b"", "headers": [(b"x-api-key", b"websocket-disconnect-test")],
        "client": ("127.0.0.1", 1234), "server": ("testserver", 80),
        "subprotocols": [], "state": {},
    }
    await incoming.put({"type": "websocket.connect"})
    previous_tasks = asyncio.all_tasks()
    task = asyncio.create_task(server.app(scope, incoming.get, send))
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2)
        if publish_event:
            hub.publish("trustlog.appended", {"test": True})
            await asyncio.wait_for(delivered.wait(), timeout=2)
        if termination == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(task), timeout=1)
        elif termination == "send_error":
            fail_send = True
            hub.publish("trustlog.appended", {"test": True})
            with pytest.raises(RuntimeError, match="synthetic send failure"):
                await asyncio.wait_for(asyncio.shield(task), timeout=1)
        else:
            await incoming.put({"type": "websocket.disconnect", "code": 1000})
            await asyncio.wait_for(asyncio.shield(task), timeout=1)
        assert not hub._subscribers
        assert not [t for t in asyncio.all_tasks() - previous_tasks if not t.done()]
    finally:
        # Wake the old blocking queue reader when verifying this test on baseline.
        hub.publish("test.cleanup", {})
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
