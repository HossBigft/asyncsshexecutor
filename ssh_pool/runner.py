import asyncio
import asyncssh
import time

from dataclasses import dataclass, field
from logging import getLogger
from typing import TypedDict


@dataclass
class RemoteHost:
    ip: str
    username: str
    name: str | None = None
    password: str | None = field(default=None, repr=False)
    private_key_path: str | None = None
    private_key_password: str | None = field(default=None, repr=False)
    port: int = 22
    jumphost: "RemoteHost | None" = None

    def __post_init__(self):
        if not (self.password or self.private_key_path):
            raise ValueError(
                "Either 'password' or 'private_key_path' must be provided for SSH authentication."
            )
        if self.name is None:
            self.name = f"{self.username}@{self.ip}:{self.port}"

    def __str__(self) -> str:
        return self.name if self.name else f"{self.username}@{self.ip}:{self.port}"

    def to_dict(self) -> dict:

        return {
            "ip": self.ip,
            "username": self.username,
            "password": "*" * len(self.password) if self.password else None,
            "private_key_path": self.private_key_path,
            "private_key_password": (
                "*" * len(self.private_key_password)
                if self.private_key_password
                else None
            ),
            "port": self.port,
            "jumphost": self.jumphost.to_dict() if self.jumphost else None,
        }


class SshResponse(TypedDict):
    stdout: str | None
    stderr: str | None
    returncode: int | None
    execution_time_s: float | None


@dataclass
class ConnectionParams:
    known_hosts: list[str] | None = None
    login_timeout_s: int = 3
    execution_timeout_s: int = 5
    connection_timeout_s: int = 15
    max_connection_timeout_s: int = 30


class SshExecutionError(Exception):
    def __init__(self, host: RemoteHost, message: str | None):
        super().__init__(f"SSH access denied for {host}: {message}")
        self.host = host
        self.message = message


class Runner:
    def __init__(self, params: ConnectionParams | None = None) -> None:
        self.connection_parameters: ConnectionParams = (
            params if params else ConnectionParams()
        )
        self._connection_pool: dict[str, asyncssh.SSHClientConnection] = {}
        self.logger = getLogger(__name__)
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()

    async def _get_host_lock(self, host: RemoteHost) -> asyncio.Lock:
        host_key: str = str(host)
        async with self._locks_lock:
            if host_key not in self._host_locks:
                self._host_locks[host_key] = asyncio.Lock()
            return self._host_locks[host_key]

    async def _connect_to_host(
        self, host: RemoteHost, tunnel: asyncssh.SSHClientConnection | None = None
    ) -> asyncssh.SSHClientConnection:
        start_time: float = time.monotonic()
        hostname: str = str(host)
        connection: asyncssh.SSHClientConnection
        try:
            if host.private_key_path:
                client_keys = asyncssh.read_private_key(
                    host.private_key_path, passphrase=host.private_key_password
                )
                connection = await asyncssh.connect(
                    host.ip,
                    username=host.username,
                    client_keys=client_keys,
                    port=host.port,
                    known_hosts=self.connection_parameters.known_hosts,
                    login_timeout=self.connection_parameters.login_timeout_s,
                    tunnel=tunnel,
                )

            else:
                connection = await asyncssh.connect(
                    host.ip,
                    username=host.username,
                    password=host.password,
                    port=host.port,
                    known_hosts=self.connection_parameters.known_hosts,
                    login_timeout=self.connection_parameters.login_timeout_s,
                    tunnel=tunnel,
                )
        except asyncio.TimeoutError as e:
            execution_time: float = time.monotonic() - start_time
            self.logger.error(
                f"Connection timed out to {hostname} in {execution_time}s: {e}"
            )
            raise SshExecutionError(
                host,
                f"Connection timed out to {hostname} in {execution_time}s: {e}",
            )
        except Exception as e:
            self.logger.error(f"Failed to create connection to {hostname}: {e}")
            raise SshExecutionError(
                host, f"Failed to create connection to {hostname}: {e}"
            )
        return connection

    async def _close_connection(self, host: str) -> bool:
        connection: asyncssh.SSHClientConnection | None = self._connection_pool.get(
            host
        )
        if connection:
            try:
                connection.close()
                await connection.wait_closed()
                self.logger.debug(f"Closed connection to {host}")
                return True
            except Exception as e:
                self.logger.error(f"Error closing connection to {host}: {e}")
                return False
        return False

    async def close_connections(self) -> None:
        self.logger.debug("Closing all SSH connections...")

        close_tasks = [self._close_connection(host) for host in self._connection_pool]
        await asyncio.gather(*close_tasks, return_exceptions=True)

        self._connection_pool.clear()
        self.logger.debug("All SSH connections closed")

    async def _get_or_create_connection(
        self, host: RemoteHost
    ) -> asyncssh.SSHClientConnection:
        host_key: str = str(host)

        connection: asyncssh.SSHClientConnection | None = self._connection_pool.get(
            host_key
        )
        if connection and not connection.is_closed():
            return connection

        host_lock: asyncio.Lock = await self._get_host_lock(host)
        async with host_lock:

            connection = self._connection_pool.get(host_key)
            if connection and not connection.is_closed():
                return connection

            if connection and connection.is_closed():
                self.logger.debug(f"Connection to {host_key} is dead, removing...")
                del self._connection_pool[host_key]
                connection = None

            if not connection:
                self.logger.debug(f"Connection to {host_key} not found, connecting...")

            jumphost_connection: asyncssh.SSHClientConnection | None = None
            if host.jumphost:
                jumphost_connection = await self._get_or_create_connection(
                    host.jumphost
                )

            connection = await self._connect_to_host(host, tunnel=jumphost_connection)
            self._connection_pool[host_key] = connection
            return connection

    async def run(self, host: RemoteHost, command: str) -> SshResponse:
        start_time: float = time.monotonic()
        try:
            connection: asyncssh.SSHClientConnection = (
                await self._get_or_create_connection(host)
            )
            result = await asyncio.wait_for(
                connection.run(command),
                timeout=self.connection_parameters.execution_timeout_s,
            )
            end_time: float = time.monotonic()
            execution_time_s: float = end_time - start_time

            stdout_output: str | None = (
                str(result.stdout.strip())
                if result.stdout and result.stdout.strip()
                else None
            )

            stderr_output: str | None = (
                str(result.stderr.strip())
                if result.stderr and result.stderr.strip()
                else None
            )

            if stderr_output:
                filtered_stderr_output: str | None = (
                    "\n".join(
                        line
                        for line in stderr_output.splitlines()
                        if not line.lower().startswith("warning: permanently added")
                    )
                    or None
                )
            else:
                filtered_stderr_output = None

            returncode_output: int | None = result.exit_status

            return {
                "stdout": stdout_output,
                "stderr": filtered_stderr_output,
                "returncode": returncode_output,
                "execution_time_s": execution_time_s,
            }

        except asyncssh.PermissionDenied as e:
            raise SshExecutionError(host, f"Permission denied: {str(e)}")

        except asyncssh.ConnectionLost as e:
            raise SshExecutionError(host, f"Connection lost: {str(e)}")

        except asyncssh.TimeoutError as e:
            execution_time_s: float = time.monotonic() - start_time
            raise SshExecutionError(
                host, f"Connection timed out in {execution_time_s}s: {str(e)}"
            )

        except asyncio.TimeoutError as e:
            execution_time_s: float = time.monotonic() - start_time
            raise SshExecutionError(
                host, f"Execution timed out in {execution_time_s}s: {str(e)}"
            )

        except asyncssh.Error as e:
            execution_time_s: float = time.monotonic() - start_time
            error_message: str = str(e).lower()
            if (
                "permission denied" in error_message
                or "authentication failed" in error_message
            ):
                raise SshExecutionError(host, str(e))

            return {
                "stdout": None,
                "stderr": str(e),
                "returncode": -1,
                "execution_time_s": execution_time_s,
            }
        finally:
            await self._close_connection(str(host))

    async def create_connection_if_missing(self, host: RemoteHost) -> None:
        await self._get_or_create_connection(host=host)


def main():
    print("Hello from runner!")


if __name__ == "__main__":
    main()
