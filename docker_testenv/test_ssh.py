from asyncssh_executor.main import AsyncSSHExecutor, SSHHost

import asyncio
import json


async def main():
    hosts: list[SSHHost] = []

    for i in range(2222, 2222 + 7):
        hosts.append(
            SSHHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    exec = AsyncSSHExecutor()

    result = await exec.execute_ssh_command(hosts[0], "ls -l /")
    print(json.dumps(result))


if __name__ == "__main__":
    asyncio.run(main())
