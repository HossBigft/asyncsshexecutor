import asyncio
import asyncssh
import time

from dataclasses import dataclass
from logging import getLogger
from typing import List, Callable, Any, TypedDict


@dataclass
class RemoteHost:
    ip: str
    username: str
    password: str | None = None
    private_key_path: str | None = None
    public_key_path: str | None = None
    port: int = 22

    def __post_init__(self):
        if not (self.password or self.private_key_path):
            raise ValueError(
                "Either 'password' or 'private_key_path' must be provided for SSH authentication."
            )

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


class SshResponse(TypedDict):
    host: str
    stdout: str | None
    stderr: str | None
    returncode: int | None
    execution_time: float | None


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
    def __init__(self, params: ConnectionParams = ConnectionParams()) -> None:
        self.connection_parameters: ConnectionParams = params
        self._connection_pool: dict[str, asyncssh.SSHClientConnection] = {}
        self.logger = getLogger()

    async def run_with_adaptive_timeout(
        self,
        coro_factory: Callable[..., Any],
        base_timeout: float = 1.0,
        factor: float = 2.0,
        max_timeout: float = 10.0,
        max_retries: int | None = None,
    ) -> Any:
        if base_timeout > max_timeout:
            tmp = max_timeout
            max_timeout = base_timeout
            base_timeout = tmp
        timeout = base_timeout
        attempt = 0

        while timeout <= max_timeout:
            try:
                return await asyncio.wait_for(coro_factory(), timeout=timeout)
            except asyncio.TimeoutError:
                if max_retries is not None:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                timeout = min(timeout * factor, max_timeout)

    async def _create_connection(
        self, host: RemoteHost
    ) -> asyncssh.SSHClientConnection:
        start_time = time.time()
        ip = host.ip
        username = host.username
        try:
            connection = await self.run_with_adaptive_timeout(
                lambda: asyncssh.connect(
                    ip,
                    username=username,
                    password=host.password,
                    port=host.port,
                    known_hosts=self.connection_parameters.known_hosts,
                    login_timeout=self.connection_parameters.login_timeout_s,
                ),
                base_timeout=self.connection_parameters.connection_timeout_s,
                max_timeout=self.connection_parameters.max_connection_timeout_s,
                max_retries=3,
            )
            self._connection_pool[ip] = connection
            return connection
        except asyncio.TimeoutError as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Connection timed out to {ip} in {execution_time}s: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to create connection to {ip}: {e}")
            raise

    async def close_connection(self) -> None:
        self.logger.info("Closing all SSH connections...")

        async def _close_single_connection(host: RemoteHost, connection):
            try:
                connection.close()
                self.logger.info(f"Closed connection to {host}")
                return True
            except Exception as e:
                self.logger.error(f"Error closing connection to {host}: {e}")
                return False

        close_tasks = [
            _close_single_connection(host, conn)
            for host, conn in self._connection_pool.items()
        ]
        await asyncio.gather(*close_tasks, return_exceptions=True)

        self._connection_pool.clear()
        self.logger.info("All SSH connections closed")

    async def _get_connection(self, host: RemoteHost) -> asyncssh.SSHClientConnection:
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

    async def _run(self, host: RemoteHost, command: str) -> SshResponse:
        start_time = time.time()
        try:
            conn = await self._get_connection(host)
            result = await asyncio.wait_for(
                conn.run(command),
                timeout=self.connection_parameters.execution_timeout_s,
            )
            end_time = time.time()
            execution_time = end_time - start_time

            stdout_output: str | None = str(
                result.stdout.strip()
                if result.stdout and result.stdout.strip() != ""
                else None
            )

            stderr_output: str | None = str(
                result.stderr.strip()
                if result.stderr and result.stderr.strip() != ""
                else None
            )

            filtered_stderr_output = None
            if stderr_output:
                stderr_lines = stderr_output.splitlines()
                filtered_stderr_output = "\n".join(
                    line
                    for line in stderr_lines
                    if not line.lower().startswith("Warning: Permanently added".lower())
                )
                filtered_stderr_output = (
                    filtered_stderr_output if filtered_stderr_output.strip() else None
                )

            returncode_output: int | None = result.exit_status

            return {
                "host": str(host),
                "stdout": stdout_output,
                "stderr": filtered_stderr_output,
                "returncode": returncode_output,
                "execution_time": execution_time,
            }

        except asyncssh.PermissionDenied as e:
            end_time = time.time()
            execution_time = end_time - start_time
            raise SshExecutionError(host, f"Permission denied: {str(e)}")

        except asyncssh.ConnectionLost as e:
            end_time = time.time()
            execution_time = end_time - start_time
            raise SshExecutionError(host, f"Connection lost: {str(e)}")

        except asyncssh.TimeoutError as e:
            end_time = time.time()
            execution_time = end_time - start_time
            raise SshExecutionError(host, f"Connection timed out: {str(e)}")

        except asyncio.TimeoutError as e:
            end_time = time.time()
            execution_time = end_time - start_time
            raise SshExecutionError(
                host, f"Execution timed out in {execution_time}s: {str(e)}"
            )

        except asyncssh.Error as e:
            end_time = time.time()
            execution_time = end_time - start_time

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
                "execution_time": execution_time,
            }

    async def run(self, host: RemoteHost, command: str) -> SshResponse:
        return await self._run(host, command)


class Pool:

    def __init__(
        self,
        hosts: list[RemoteHost],
        params: ConnectionParams = ConnectionParams(),
        max_concurrency: int = 100,
    ) -> None:
        if not hosts:
            raise ValueError("At least one SSH server must be provided.")

        self.executor: Runner = Runner(params=params)
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
        ) -> tuple[RemoteHost, asyncssh.SSHClientConnection | Exception]:
            async with semaphore:
                try:
                    connection = await self.executor._get_connection(host)
                    return host, connection
                except Exception as exc:
                    return host, exc

        connection_tasks = []
        for host in self.hosts.values():
            connection_tasks.append(_create_connection_with_limit(host))

        results = await asyncio.gather(*connection_tasks, return_exceptions=True)

        successful_connections = 0
        failed_connections = 0

        for result in results:
            if isinstance(result, Exception):
                self.logger.error("Failed to connect: %s", result)
                failed_connections += 1
                continue

            host, _ = result
            self.logger.info("Successfully connected to %s", host)
            successful_connections += 1
        execution_time = time.monotonic() - start_time

        self.logger.info(
            f"Connection pool initialized in {execution_time}s: {successful_connections} successful, {failed_connections} failed"
        )

    async def run(
        self, command: str
    ) -> List[SshResponse | Exception]:
        start_time: float = time.time()
        semaphore = asyncio.Semaphore(100)

        async def worker(host: RemoteHost):
            async with semaphore:
                try:
                    return await self.executor._run(host, command)
                except Exception as e:
                    return e

        results = await asyncio.gather(*(worker(host) for host in self.hosts.values()))
        end_time: float = time.time()
        execution_time: float = end_time - start_time
        self.logger.info(
            f"Batch size of {len(self.hosts.values())} executed in {execution_time}s."
        )
        return results


def main():
    print("Hello from asyncssh-executor!")


if __name__ == "__main__":
    main()
