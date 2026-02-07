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
    ssh_runner = Runner()
    result = await ssh_runner.run(hosts[0], "ls -l /")
    print(json.dumps(result))

    # print("Batch run without warmup")
    ssh_password_pool = Pool(hosts=hosts)
    results = await ssh_password_pool.run("ls -l /")
    print(json.dumps(results))

    await ssh_password_pool.warmup()
    # print("Batch run after warmup")
    results = await ssh_password_pool.run("ls -l /")
    print(json.dumps(results))
    
    
    key_hosts: list[RemoteHost] = [] 
    for i in range(2222, 2222 + 5):
        key_hosts.append(
            RemoteHost(ip="127.0.0.1", username="testuser", password="testpass", port=i)
        )
    ssh_key_pool = Pool(hosts=key_hosts)
    results = await ssh_key_pool.run("ls -l /")
    print(json.dumps(results))

if __name__ == "__main__":
    uvloop.run(main())
