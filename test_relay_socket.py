import asyncio

from stem.client import DEFAULT_LINK_PROTOCOLS
from stem.client.cell import VersionsCell
from stem.async_socket import RelaySocket


async def run_command(i, command):
  async with RelaySocket(address='127.0.0.1', port=443) as cp:
    print(f'{i} Connecting')
    await cp.connect()
    print(f'{i} Sending the command')
    await cp.send(command)
    print(f'{i} Receiving result of the command')
    result = await cp.recv(2)
    print(result)


if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  tasks = asyncio.gather(
    run_command(1, VersionsCell(DEFAULT_LINK_PROTOCOLS).pack(2)),
    run_command(2, VersionsCell(DEFAULT_LINK_PROTOCOLS).pack(2)),
  )
  try:
    loop.run_until_complete(tasks)
  finally:
    loop.close()
