from ssh_pool.runner import Runner, RemoteHost


def main():
    params = RemoteHost(ip="127.0.0.1", username="testuser", password="testpass")
    exec = Runner()
    print(exec.run(params, "ls -l /"))


if __name__ == "__main__":
    main()
