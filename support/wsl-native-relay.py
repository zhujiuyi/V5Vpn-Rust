import asyncio
from contextlib import suppress
from ipaddress import IPv4Address
import socket
import struct
import sys


# Linux netfilter supplies the target from before the PREROUTING REDIRECT.
SO_ORIGINAL_DST = 80


def original_destination(connection):
    address = connection.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    family, = struct.unpack_from("=H", address)
    if family != socket.AF_INET:
        raise OSError("expected an IPv4 destination")
    port, = struct.unpack_from("!H", address, 2)
    return socket.inet_ntoa(address[4:8]), port


async def copy(source, destination):
    while data := await source.read(65536):
        destination.write(data)
        await destination.drain()
    destination.write_eof()


async def serve(host, bridge_port, nonce, targets):
    # Verify the host listener is reachable before installing the guest rules.
    async with asyncio.timeout(3):
        _, probe = await asyncio.open_connection(host, bridge_port)
        probe.close()
        with suppress(OSError):
            await probe.wait_closed()

    slots = asyncio.Semaphore(128)

    async def accept(client, local):
        remote = None
        try:
            if local.get_extra_info("peername")[0] != host or slots.locked():
                return
            target, port = original_destination(local.get_extra_info("socket"))
            if target not in targets or port == 0:
                return

            async with slots:
                async with asyncio.timeout(25):
                    bridge, remote = await asyncio.open_connection(host, bridge_port)
                    remote.write(nonce + socket.inet_aton(target) + struct.pack("!H", port))
                    await remote.drain()
                    if await bridge.readexactly(1) != b"\x01":
                        return
                try:
                    async with asyncio.TaskGroup() as copies:
                        copies.create_task(copy(client, remote))
                        copies.create_task(copy(bridge, local))
                except* OSError:
                    pass
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            local.close()
            if remote is not None:
                remote.close()

    server = await asyncio.start_server(accept, host="0.0.0.0", port=0, family=socket.AF_INET)
    async with server:
        print(server.sockets[0].getsockname()[1], flush=True)
        await server.serve_forever()


def unicast(value):
    address = IPv4Address(value)
    if (address.is_unspecified or address.is_loopback or address.is_multicast
            or address == IPv4Address("255.255.255.255")):
        raise ValueError("expected a unicast IPv4 address")
    return str(address)


def main():
    host, bridge_port, nonce, *values = sys.stdin.readline().split()
    host = unicast(host)
    bridge_port = int(bridge_port)
    nonce = bytes.fromhex(nonce)
    targets = {unicast(value) for value in values}
    if not 0 < bridge_port <= 65535 or len(nonce) != 32 or not targets or host in targets:
        raise ValueError("invalid relay configuration")
    asyncio.run(serve(host, bridge_port, nonce, targets))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError):
        sys.exit(1)
