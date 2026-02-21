import asyncio
import asyncssh
import time

from dataclasses import dataclass, field
from logging import getLogger
from typing import cast


@dataclass
class RemoteHost:
    username: str
    ip: str | None = None
    domain: str | None = None
    name: str | None = None
    password: str | None = field(default=None, repr=False)
    private_key_path: str | None = None
    private_key_password: str | None = field(default=None, repr=False)
    port: int = 22
    jumphost: "RemoteHost | None" = None
    _address: str = field(init=False)

    def __post_init__(self):
        if not (self.ip or self.domain):
            raise ValueError(
                "Either 'IP' or 'domain' must be provided for SSH connection."
            )
        self._address = cast(str, self.ip or self.domain)

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

    def address(self) -> str:
        return self._address


@dataclass
class ExecutionResult:
    stdout: str | None
    stderr: str | None
    returncode: int | None
    execution_time_s: float | None

    def to_dict(self) -> dict:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "retruncode": self.returncode,
            "execution_time_s": self.execution_time_s,
        }


class ExecutionError(Exception):
    def __init__(self, host: RemoteHost, message: str | None):
        super().__init__(f"SSH access denied for {host}: {message}")
        self.host = host
        self.message = message


class Executor:
    def __init__(
        self,
        connection: asyncssh.SSHClientConnection | None = None,
        execution_timeout_s: int = 5,
    ) -> None:
        self.connection = connection
        self.execution_timeout_s = execution_timeout_s
        self.logger = getLogger(__name__)

    async def execute(self, host: RemoteHost, command: str) -> ExecutionResult:
        if not self.connection:
            raise ValueError("No connection provided")

        start_time: float = time.monotonic()
        try:

            result = await asyncio.wait_for(
                self.connection.run(command),
                timeout=self.execution_timeout_s,
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

            return ExecutionResult(
                stdout=stdout_output,
                stderr=filtered_stderr_output,
                returncode=returncode_output,
                execution_time_s=execution_time_s,
            )

        except asyncio.TimeoutError as e:
            execution_time_s: float = time.monotonic() - start_time
            raise ExecutionError(
                host, f"Execution timed out in {execution_time_s}s"
            ) from e

        except asyncssh.Error as e:
            execution_time_s: float = time.monotonic() - start_time
            error_message: str = str(e).lower()
            if (
                "permission denied" in error_message
                or "authentication failed" in error_message
            ):
                raise ExecutionError(host, str(e)) from e

            return ExecutionResult(
                stdout=None,
                stderr=str(e),
                returncode=-1,
                execution_time_s=execution_time_s,
            )


def main():
    print("Hello from runner!")


if __name__ == "__main__":
    main()
