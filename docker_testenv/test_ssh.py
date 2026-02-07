from asyncssh_executor.main import AsyncSSHExecutor, SSHHost, AsyncBatchSSHExecutor

import asyncio
import json


async def main():
    hosts: list[SSHHost] = []

    for i in range(2222, 2222 + 5):
        hosts.append(
            SSHHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    # print("Single run")
    exec = AsyncSSHExecutor()
    result = await exec.execute_ssh_command(hosts[0], "ls -l /")
    print(json.dumps(result))

    # print("Batch run without warmup")
    batch = AsyncBatchSSHExecutor(hosts=hosts)
    results = await batch.execute_ssh_commands_in_batch("ls -l /")
    print(json.dumps(results))
    
    # print("Batch run after warmup")
    results = await batch.execute_ssh_commands_in_batch("ls -l /")
    print(json.dumps(results))


if __name__ == "__main__":
    asyncio.run(main())
