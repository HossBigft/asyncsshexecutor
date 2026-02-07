from ssh_pool.runner import Runner, RemoteHost

import asyncio
import json


async def main():
    hosts: list[RemoteHost] = []

    for i in range(2222, 2222 + 7):
        hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    exec = Runner()

    result = await exec.run(hosts[0], "ls -l /")
    print(json.dumps(result))


if __name__ == "__main__":
    asyncio.run(main())
