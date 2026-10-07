from __future__ import annotations

import asyncio
from typing import Any, cast

from dbus_fast import BusType, Variant
from dbus_fast.aio import MessageBus

from src.config import ACTION_ID


class AuthorizationDenied(Exception):
    """Distinguishes an unavailable or rejected Polkit check from other failures."""


async def authorize_async(timeout: float = 60.0) -> None:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        name = "org.freedesktop.PolicyKit1"
        path = "/org/freedesktop/PolicyKit1/Authority"
        introspection = await bus.introspect(name, path)
        obj = bus.get_proxy_object(name, path, introspection)
        authority = cast(Any, obj.get_interface("org.freedesktop.PolicyKit1.Authority"))
        subject = ("system-bus-name", {"name": Variant("s", bus.unique_name)})
        result = await asyncio.wait_for(
            authority.call_check_authorization(subject, ACTION_ID, {}, 1, ""), timeout
        )
        if not result[0]:
            raise AuthorizationDenied("user verification was denied")
    finally:
        bus.disconnect()


def authorize() -> None:
    try:
        asyncio.run(authorize_async())
    except (AuthorizationDenied, TimeoutError):
        raise
    except Exception as exc:
        raise AuthorizationDenied(f"Polkit authorization unavailable: {exc}") from exc
