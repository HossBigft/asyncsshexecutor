from asyncssh_executor.main import Runner, RemoteHost


def main():
    params = RemoteHost(ip="127.0.0.1", username="testuser", password="testpass")
    exec = Runner()
    print(exec.execute_ssh_command(params, "ls -l /"))


if __name__ == "__main__":
    main()
