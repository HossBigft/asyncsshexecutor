import asyncio
import asyncssh
import time

from dataclasses import dataclass, field
from logging import getLogger
from typing import List, TypedDict


@dataclass
class RemoteHost:
    ip: str
    username: str
    password: str | None = field(default=None, repr=False)
    private_key_path: str | None = None
    port: int = 22

    def __post_init__(self):
        if not (self.password or self.private_key_path):
            raise ValueError(
                "Either 'password' or 'private_key_path' must be provided for SSH authentication."
            )

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"

    def to_dict(self) -> dict:

        return {
            "ip": self.ip,
            "username": self.username,
            "password": "*" * len(self.password) if self.password else None,
            "private_key_path": self.private_key_path,
            "port": self.port,
        }


class SshResponse(TypedDict):
    host: str
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
        self.logger = getLogger()
        self._conn_lock = asyncio.Lock()

    async def _create_connection(
        self, host: RemoteHost
    ) -> asyncssh.SSHClientConnection:
        start_time = time.monotonic()
        hostname = str(host)
        username = host.username
        async with self._conn_lock:
            try:
                connection: asyncssh.SSHClientConnection
                if host.private_key_path:
                    connection = await asyncssh.connect(
                        host.ip,
                        username=username,
                        client_keys=host.private_key_path,
                        port=host.port,
                        known_hosts=self.connection_parameters.known_hosts,
                        login_timeout=self.connection_parameters.login_timeout_s,
                    )

                else:
                    connection = await asyncssh.connect(
                        host.ip,
                        username=username,
                        password=host.password,
                        port=host.port,
                        known_hosts=self.connection_parameters.known_hosts,
                        login_timeout=self.connection_parameters.login_timeout_s,
                    )

                self._connection_pool[hostname] = connection
                return connection
            except asyncio.TimeoutError as e:
                execution_time = time.monotonic() - start_time
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

    async def _close_connection(self, host: str) -> bool:
        connection: asyncssh.SSHClientConnection | None = self._connection_pool.get(
            host
        )
        if connection:
            try:
                connection.close()
                await connection.wait_closed()
                self.logger.info(f"Closed connection to {host}")
                return True
            except Exception as e:
                self.logger.error(f"Error closing connection to {host}: {e}")
                return False
        return False

    async def close_connections(self) -> None:
        self.logger.info("Closing all SSH connections...")

        close_tasks = [self._close_connection(host) for host in self._connection_pool]
        await asyncio.gather(*close_tasks, return_exceptions=True)

        self._connection_pool.clear()
        self.logger.info("All SSH connections closed")

    async def _get_or_create_connection(
        self, host: RemoteHost
    ) -> asyncssh.SSHClientConnection:
        ip = host.ip
        connection: asyncssh.SSHClientConnection | None = self._connection_pool.get(ip)
        if not connection:
            self.logger.info(f"Connection to {ip} is not found, creating.")
            connection = await self._create_connection(host)
            self._connection_pool[ip] = connection
            return connection
        if connection.is_closed():
            self.logger.warning(f"Connection to {ip} is dead, recreating...")
            connection = await self._create_connection(host)
            self._connection_pool[ip] = connection
            return connection
        else:
            return connection

    async def run(self, host: RemoteHost, command: str) -> SshResponse:
        start_time = time.monotonic()
        try:
            conn = await self._get_or_create_connection(host)
            result = await asyncio.wait_for(
                conn.run(command),
                timeout=self.connection_parameters.execution_timeout_s,
            )
            end_time = time.monotonic()
            execution_time_s = end_time - start_time

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
                filtered_stderr_output = (
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
                "host": str(host),
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
            execution_time_s = time.monotonic() - start_time
            raise SshExecutionError(
                host, f"Connection timed out in {execution_time_s}s: {str(e)}"
            )

        except asyncio.TimeoutError as e:
            execution_time_s = time.monotonic() - start_time
            raise SshExecutionError(
                host, f"Execution timed out in {execution_time_s}s: {str(e)}"
            )

        except asyncssh.Error as e:
            execution_time_s = time.monotonic() - start_time
            error_message = str(e).lower()
            if (
                "permission denied" in error_message
                or "authentication failed" in error_message
            ):
                raise SshExecutionError(host, str(e))

            return {
                "host": str(host),
                "stdout": None,
                "stderr": str(e),
                "returncode": -1,
                "execution_time_s": execution_time_s,
            }
        finally:
            await self._close_connection(str(host))

    async def create_connection_if_missing(self, host: RemoteHost) -> None:
        await self._get_or_create_connection(host=host)


@dataclass
class HostResult:
    host: str
    response: SshResponse | None = None
    error: Exception | None = None

    def success(self) -> bool:
        return True if not self.error else False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "success": self.success(),
            "response": self.response,
            "error": str(self.error) if self.error else None,
        }


class Pool:

    def __init__(
        self,
        hosts: list[RemoteHost],
        params: ConnectionParams | None = None,
        max_concurrency: int = 100,
    ) -> None:
        if not hosts:
            raise ValueError("At least one SSH server must be provided.")

        self.executor: Runner = Runner(params=params if params else ConnectionParams())
        self.hosts: dict[str, RemoteHost] = {str(host): host for host in hosts}
        self.max_concurrency = max_concurrency
        self.logger = getLogger()

    async def warmup(self) -> None:
        self.logger.info(
            f"Initializing SSH connection pool for {len(self.hosts)} servers..."
        )
        start_time = time.monotonic()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _create_connection_with_limit(
            host: RemoteHost,
        ) -> tuple[RemoteHost, Exception | None]:
            async with semaphore:
                try:
                    await self.executor.create_connection_if_missing(host)
                    return host, None
                except Exception as exc:
                    return host, exc

        connection_tasks = []
        for host in self.hosts.values():
            connection_tasks.append(_create_connection_with_limit(host))

        results = await asyncio.gather(*connection_tasks, return_exceptions=False)

        successful_connections = 0
        failed_connections = 0

        for result in results:
            host, exception = result
            if exception:
                self.logger.error(f"Failed to connect to {host}: {exception}")
                failed_connections += 1
                continue

            self.logger.info(f"Successfully connected to {host}")
            successful_connections += 1
        execution_time = time.monotonic() - start_time

        self.logger.info(
            f"Connection pool initialized in {execution_time}s: {successful_connections} successful, {failed_connections} failed"
        )

    async def run(self, command: str) -> List[HostResult]:
        start_time: float = time.monotonic()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def worker(host: RemoteHost):
            host_result: HostResult = HostResult(host=str(host))
            async with semaphore:
                try:
                    host_result.response = await self.executor.run(host, command)
                except Exception as e:
                    host_result.error = e
            return host_result

        results = await asyncio.gather(*(worker(host) for host in self.hosts.values()))
        end_time: float = time.monotonic()
        execution_time: float = end_time - start_time
        self.logger.info(
            f"Batch size of {len(self.hosts.values())} executed in {execution_time}s."
        )
        return results

    async def run_on_host(self, host: RemoteHost, command: str) -> SshResponse:
        return await self.executor.run(host=host, command=command)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "executor"):
            await self.executor.close_connections()
        return False


def main():
    print("Hello from asyncssh-executor!")


if __name__ == "__main__":
    main()
