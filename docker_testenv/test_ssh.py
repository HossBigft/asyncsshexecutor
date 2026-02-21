import json
import uvloop
import sys

from ssh_pool.pool import RemoteHost, Pool


async def main():
    hosts: list[RemoteHost] = []

    for i in range(2222, 2222 + 5):
        hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )

    sys.stderr.write("Batch run without warmup")
    ssh_password_pool = Pool(hosts=hosts)
    async for result in ssh_password_pool.execute("ls -l /"):
        print(json.dumps(result.to_dict()))

    await ssh_password_pool.warmup()
    sys.stderr.write("Batch run after warmup")

    async for result in ssh_password_pool.execute("ls -l /"):
        print(json.dumps(result.to_dict()))

    key_hosts: list[RemoteHost] = []
    for i in range(2222, 2222 + 5):
        key_hosts.append(
            RemoteHost(
                ip="127.0.0.1",
                username="testuser",
                port=i,
                private_key_path="./docker_testenv/test_key",
            )
        )
    async with Pool(hosts=key_hosts) as ssh_pool_keyauth:
        await ssh_pool_keyauth.warmup()
        async for result in ssh_pool_keyauth.execute("ls -l /"):
            print(json.dumps(result.to_dict()))

        result = await ssh_pool_keyauth.execute_on_host(
            host=key_hosts[0], command="ls -l /"
        )
        print(json.dumps(result.to_dict()))


if __name__ == "__main__":
    uvloop.run(main())
