import time
import asyncio
import asyncssh

from logging import getLogger
from dataclasses import dataclass

from typing import TypedDict, NotRequired, AsyncGenerator

from ssh_pool.runner import Executor, ExecutionResult, RemoteHost


class ErrorDict(TypedDict):
    type: str
    message: str
    cause: NotRequired["ErrorDict"]


@dataclass
class HostResult:
    host: RemoteHost
    response: ExecutionResult | None = None
    error: Exception | None = None

    def success(self) -> bool:
        return self.error is None

    def serialize_error(self, e: Exception | BaseException) -> ErrorDict:

        result: ErrorDict = {
            "type": type(e).__name__,
            "message": str(e),
        }

        if e.__cause__:
            result["cause"] = self.serialize_error(e.__cause__)

        return result

    def to_dict(self, verbose: bool = False) -> dict:
        return {
            "host": self.host if verbose else str(self.host),
            "success": self.success(),
            "response": self.response.to_dict() if self.response else None,
            "error": self.serialize_error(self.error) if self.error else None,
        }


@dataclass
class ConnectionParams:
    known_hosts: list[str] | None = None
    login_timeout_s: int = 3
    execution_timeout_s: int = 5
    connection_timeout_s: int = 15
    max_connection_timeout_s: int = 30


class ConnectionError(Exception):
    def __init__(self, host: RemoteHost, message: str | None):
        super().__init__(f"{host}: {message}")
        self.host = host
        self.message = message


class _ConnectionPool:
    def __init__(
        self,
        hosts: list[RemoteHost],
        connection_parameters: ConnectionParams | None = None,
        max_concurrent_handshakes: int = 5,
    ) -> None:
        if not hosts:
            raise ValueError("At least one SSH server must be provided.")
        if not connection_parameters:
            self.connection_parameters = ConnectionParams()
        if isinstance(hosts, RemoteHost):
            hosts = [hosts]
        self.logger = getLogger(__name__)

        self.hosts: dict[str, RemoteHost] = {str(host): host for host in hosts}
        self.max_concurrent_handshakes = max_concurrent_handshakes

        self._host_locks: dict[str, asyncio.Lock] = {}
        self._locks_lock = asyncio.Lock()
        self._keys: dict[str, asyncssh.SSHKey] = {}
        self._key_locks: dict[str, asyncio.Lock] = {}
        self._keydict_lock = asyncio.Lock()
        self._connection_pool: dict[str, asyncssh.SSHClientConnection] = {}

    async def warmup(self) -> None:
        self.logger.info(
            f"Initializing SSH connection pool for {len(self.hosts)} servers..."
        )
        start_time = time.monotonic()
        semaphore = asyncio.Semaphore(self.max_concurrent_handshakes)

        async def _create_connection_with_limit(
            host: RemoteHost,
        ) -> tuple[RemoteHost, Exception | None]:
            async with semaphore:
                try:
                    await self._get_or_create_connection(host)
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

    async def _get_host_lock(self, host: RemoteHost) -> asyncio.Lock:
        host_key: str = str(host)
        async with self._locks_lock:
            if host_key not in self._host_locks:
                self._host_locks[host_key] = asyncio.Lock()
            return self._host_locks[host_key]

    async def _get_key_lock(self, key_path: str) -> asyncio.Lock:
        async with self._keydict_lock:
            lock = self._key_locks.get(key_path)
            if lock is None:
                lock = asyncio.Lock()
                self._key_locks[key_path] = lock
            return lock

    async def _get_key(self, path: str, passphrase: str | None):
        key_id = path

        key = self._keys.get(key_id)
        if key is not None:
            return key

        key_lock = await self._get_key_lock(key_id)

        async with key_lock:
            key = self._keys.get(key_id)
            if key is not None:
                return key

            key = await asyncio.to_thread(
                asyncssh.read_private_key,
                path,
                passphrase=passphrase,
            )

            self._keys[key_id] = key
            return key

    async def _connect_to_host(
        self, host: RemoteHost, tunnel: asyncssh.SSHClientConnection | None = None
    ) -> asyncssh.SSHClientConnection:
        start_time: float = time.monotonic()
        hostname: str = str(host)
        connection: asyncssh.SSHClientConnection
        try:
            if host.private_key_path:
                key = await self._get_key(
                    host.private_key_path, host.private_key_password
                )
                connection = await asyncssh.connect(
                    host=host.address(),
                    username=host.username,
                    client_keys=key,
                    port=host.port,
                    known_hosts=self.connection_parameters.known_hosts,
                    login_timeout=self.connection_parameters.login_timeout_s,
                    tunnel=tunnel,
                )

            else:
                connection = await asyncssh.connect(
                    host=host.address(),
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
            raise ConnectionError(
                host,
                f"Connection timed out to {hostname} in {execution_time}s",
            ) from e
        except asyncssh.ConnectionLost as e:
            execution_time: float = time.monotonic() - start_time
            self.logger.error(
                f"Login timeout expired to {hostname} in {execution_time}s: {e}"
            )
            raise ConnectionError(
                host,
                f"Login timeout expired to {hostname} in {execution_time}s",
            ) from e
        except asyncssh.ChannelOpenError as e:
            self.logger.error(f"{hostname} is not responding on port {host.port}")
            raise ConnectionError(
                host,
                f"{hostname} is not responding on port {host.port}",
            ) from e
        except asyncssh.PermissionDenied as e:

            if host.private_key_path:
                auth = host.private_key_path
            elif host.password:
                auth = "*" * len(host.password)
            else:
                auth = "no credentials"

            self.logger.error(f"Authentification failed for {hostname} with {auth}")
            raise ConnectionError(
                host,
                f"{hostname} is not responding on port {host.port}",
            ) from e
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


class Pool:

    def __init__(
        self,
        hosts: list[RemoteHost],
        connection_parameters: ConnectionParams | None = None,
        max_concurrent_commands: int = 100,
    ) -> None:
        if not hosts:
            raise ValueError("At least one SSH server must be provided.")
        if not connection_parameters:
            self.connection_parameters = ConnectionParams()
        if isinstance(hosts, RemoteHost):
            hosts = [hosts]
        self.logger = getLogger(__name__)

        self._connection_pool = _ConnectionPool(
            hosts=hosts, connection_parameters=connection_parameters
        )
        self._executors: dict[str, Executor] = {str(host): Executor() for host in hosts}
        self.max_concurrency = max_concurrent_commands

    async def execute(self, command: str) -> AsyncGenerator[HostResult]:

        start_time: float = time.monotonic()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def worker(host: RemoteHost):
            host_result: HostResult = HostResult(host=host)
            executor: Executor = self._executors.setdefault(str(host), Executor())
            
            async with semaphore:
                try:
                    connection: asyncssh.SSHClientConnection = (
                        await self._connection_pool._get_or_create_connection(host)
                    )
                except ConnectionError as e:
                    host_result.error = e
                    return host_result
                executor.connection = connection

                try:
                    host_result.response = await executor.execute(host, command)
                except Exception as e:
                    host_result.error = e
            return host_result

        for coroutine in asyncio.as_completed(
            worker(host) for host in self._connection_pool.hosts.values()
        ):
            yield await coroutine
        end_time: float = time.monotonic()
        execution_time: float = end_time - start_time
        self.logger.info(
            f"Batch size of {len(self._connection_pool.hosts)} executed in {execution_time}s."
        )

    async def execute_on_host(self, host: RemoteHost, command: str) -> ExecutionResult:
        executor: Executor = self._executors.setdefault(str(host), Executor())
        return await executor.execute(host=host, command=command)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, "executor"):
            await self._connection_pool.close_connections()
        return False

    async def warmup(self) -> None:
        await self._connection_pool.warmup()


def main():
    print("Hello from ssh pool!")


if __name__ == "__main__":
    main()
