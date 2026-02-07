from ssh_pool.runner import Runner, RemoteHost, Pool

import json
import uvloop

async def main():
    hosts: list[RemoteHost] = []

    for i in range(2222, 2222 + 5):
        hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    # print("Single run")
    exec = Runner()
    result = await exec.run(hosts[0], "ls -l /")
    print(json.dumps(result))

    # print("Batch run without warmup")
    batch = Pool(hosts=hosts)
    results = await batch.run("ls -l /")
    print(json.dumps(results))

    await batch.warmup()
    # print("Batch run after warmup")
    results = await batch.run("ls -l /")
    print(json.dumps(results))


if __name__ == "__main__":
    uvloop.run(main())
