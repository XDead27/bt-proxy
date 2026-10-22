"""Temporary BlueZ pairing agent used while the proxy pairs a device.

BlueZ asks an agent to confirm even "Just Works" pairing; with no agent
registered it rejects the confirmation itself and the pairing fails with
"Numeric comparison failed". BlueZ also only creates a bond (rather than a
throwaway pairing) while the adapter is Pairable. So for the duration of one
pairing we register an agent that auto-confirms that one device, make it the
default agent (bleak's Pair() call comes from a different D-Bus connection),
and switch the adapter to Pairable — then undo all of it.
"""

# No `from __future__ import annotations` here: dbus_fast reads the D-Bus
# signatures from the method annotations at class creation time.

import contextlib
import logging
import uuid
from typing import AsyncIterator

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.errors import DBusError
from dbus_fast.service import ServiceInterface, method

logger = logging.getLogger(__name__)

BLUEZ_SERVICE = "org.bluez"
AGENT_MANAGER_PATH = "/org/bluez"
AGENT_MANAGER_INTERFACE = "org.bluez.AgentManager1"
ADAPTER_INTERFACE = "org.bluez.Adapter1"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
ERROR_REJECTED = "org.bluez.Error.Rejected"

# Same capability HueBLE registers for its own BlueZ pairing workaround.
AGENT_CAPABILITY = "KeyboardDisplay"


class _AutoConfirmAgent(ServiceInterface):
    """org.bluez.Agent1 that accepts confirmation for exactly one device.

    Anything that needs real user input (PIN / passkey entry) or concerns a
    different device is rejected, so the agent can't be used to pair other
    devices while it is registered.
    """

    def __init__(self, device_path: str):
        super().__init__("org.bluez.Agent1")
        self._device_path = device_path

    def _check_device(self, device: str) -> None:
        if device != self._device_path:
            logger.warning("Rejecting pairing request from %s", device)
            raise DBusError(ERROR_REJECTED, "Not the device being paired")

    @method()
    def Release(self):
        pass

    @method()
    def RequestConfirmation(self, device: "o", passkey: "u"):
        self._check_device(device)
        logger.debug("Auto-confirming passkey %06d for %s", passkey, device)

    @method()
    def RequestAuthorization(self, device: "o"):
        self._check_device(device)
        logger.debug("Auto-authorizing %s", device)

    @method()
    def AuthorizeService(self, device: "o", uuid: "s"):
        raise DBusError(ERROR_REJECTED, "Service authorization not supported")

    @method()
    def RequestPinCode(self, device: "o") -> "s":
        raise DBusError(ERROR_REJECTED, "PIN entry not supported")

    @method()
    def RequestPasskey(self, device: "o") -> "u":
        raise DBusError(ERROR_REJECTED, "Passkey entry not supported")

    @method()
    def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):
        pass

    @method()
    def DisplayPinCode(self, device: "o", pincode: "s"):
        pass

    @method()
    def Cancel(self):
        logger.debug("Pairing cancelled by BlueZ")


async def _call(bus: MessageBus, **kwargs) -> Message:
    reply = await bus.call(Message(destination=BLUEZ_SERVICE, **kwargs))
    assert reply is not None
    if reply.message_type == MessageType.ERROR:
        raise DBusError(reply.error_name, " ".join(map(str, reply.body)))
    return reply


async def _get_pairable(bus: MessageBus, adapter_path: str) -> bool:
    reply = await _call(
        bus,
        path=adapter_path,
        interface=PROPERTIES_INTERFACE,
        member="Get",
        signature="ss",
        body=[ADAPTER_INTERFACE, "Pairable"],
    )
    return bool(reply.body[0].value)


async def _set_pairable(bus: MessageBus, adapter_path: str, value: bool) -> None:
    await _call(
        bus,
        path=adapter_path,
        interface=PROPERTIES_INTERFACE,
        member="Set",
        signature="ssv",
        body=[ADAPTER_INTERFACE, "Pairable", Variant("b", value)],
    )


@contextlib.asynccontextmanager
async def pairing_agent(device_path: str) -> AsyncIterator[None]:
    """Make BlueZ able to bond with ``device_path`` while the block runs.

    ``device_path`` is the BlueZ object path, e.g.
    ``/org/bluez/hci0/dev_E8_25_17_3F_2B_21``.
    """
    adapter_path = device_path.rsplit("/", 1)[0]
    agent_path = f"/org/btproxy/agent_{uuid.uuid4().hex[:8]}"
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    agent = _AutoConfirmAgent(device_path)
    bus.export(agent_path, agent)
    registered = False
    restore_pairable = False
    try:
        await _call(
            bus,
            path=AGENT_MANAGER_PATH,
            interface=AGENT_MANAGER_INTERFACE,
            member="RegisterAgent",
            signature="os",
            body=[agent_path, AGENT_CAPABILITY],
        )
        registered = True
        await _call(
            bus,
            path=AGENT_MANAGER_PATH,
            interface=AGENT_MANAGER_INTERFACE,
            member="RequestDefaultAgent",
            signature="o",
            body=[agent_path],
        )
        if not await _get_pairable(bus, adapter_path):
            await _set_pairable(bus, adapter_path, True)
            restore_pairable = True
        yield
    finally:
        if restore_pairable:
            try:
                await _set_pairable(bus, adapter_path, False)
            except Exception as e:
                logger.warning("Could not restore Pairable=false: %s", e)
        if registered:
            try:
                await _call(
                    bus,
                    path=AGENT_MANAGER_PATH,
                    interface=AGENT_MANAGER_INTERFACE,
                    member="UnregisterAgent",
                    signature="o",
                    body=[agent_path],
                )
            except Exception as e:
                logger.warning("Could not unregister pairing agent: %s", e)
        bus.unexport(agent_path, agent)
        bus.disconnect()
