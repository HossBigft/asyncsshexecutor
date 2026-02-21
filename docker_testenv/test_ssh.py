import json
import uvloop

from ssh_pool.runner import Executor
from ssh_pool.pool import RemoteHost, Pool


async def main():
    hosts: list[RemoteHost] = []

    for i in range(2222, 2222 + 5):
        hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    # # print("Single run")
    # ssh_runner = Executor()
    # result = await ssh_runner.execute(hosts[0], "ls -l /")
    # print(json.dumps(result))

    # print("Batch run without warmup")
    ssh_password_pool = Pool(hosts=hosts)
    results = await ssh_password_pool.execute("ls -l /")
    print(json.dumps([r.to_dict() for r in results]))

    await ssh_password_pool.warmup()
    # print("Batch run after warmup")
    results = await ssh_password_pool.execute("ls -l /")
    print(json.dumps([r.to_dict() for r in results]))

    key_hosts: list[RemoteHost] = []
    for i in range(2222, 2222 + 5):
        key_hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", port=i, private_key_path='./docker_testenv/test_key')
        )
    async with Pool(hosts=key_hosts) as ssh_key_pool:
        await ssh_key_pool.warmup()
        results = await ssh_key_pool.execute("ls -l /")
        print(json.dumps([r.to_dict() for r in results]))

        result = await ssh_key_pool.execute_on_host(host=key_hosts[0], command="ls -l /")
        print(json.dumps(result.to_dict()))


if __name__ == "__main__":
    uvloop.run(main())
