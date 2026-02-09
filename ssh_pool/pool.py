import time
import asyncio

from logging import getLogger
from dataclasses import dataclass
from ssh_pool.runner import Runner, SshResponse, RemoteHost, ConnectionParams


@dataclass
class HostResult:
    host: RemoteHost
    response: SshResponse | None = None
    error: Exception | None = None

    def success(self) -> bool:
        return self.error is None

    def to_dict(self, verbose: bool = False) -> dict:
        return {
            "host": self.host if verbose else str(self.host),
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

        if isinstance(hosts, RemoteHost):
            hosts = [hosts]

        self.executor: Runner = Runner(params=params if params else ConnectionParams())
        self.hosts: dict[str, RemoteHost] = {str(host): host for host in hosts}
        self.max_concurrency = max_concurrency
        self.logger = getLogger(__name__)

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

    async def run(self, command: str) -> list[HostResult]:
        start_time: float = time.monotonic()
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def worker(host: RemoteHost):
            host_result: HostResult = HostResult(host=host)
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
    print("Hello from ssh pool!")


if __name__ == "__main__":
    main()
