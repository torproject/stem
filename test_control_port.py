import asyncio

from stem.async_socket import ControlPort


async def run_command(i, command):
  async with ControlPort() as cp:
    print(f'{i} Connecting')
    await cp.connect()
    print(f'{i} Authenticating')
    await cp.send('AUTHENTICATE "password"')
    print(f'{i} Receiving auth message')
    await cp.recv()
    print(f'{i} Sending the command')
    await cp.send(command)
    print(f'{i} Receiving result of the command')
    result = await cp.recv()
    print(f'{i} {result.content()}')


if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  tasks = asyncio.gather(
    run_command(1, 'PROTOCOLINFO 1'),
    run_command(2, 'GETINFO traffic/read'),
  )
  try:
    loop.run_until_complete(tasks)
  finally:
    loop.close()
