"""One module contract shared by the CLI and interactive console."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from rich.console import Console


@dataclass(frozen=True)
class Option:
    name: str
    kind: type
    default: Any
    description: str
    flag: str

    def parse(self, value: str) -> Any:
        if self.kind is bool:
            if value.lower() not in {"true", "false", "yes", "no", "1", "0"}:
                raise ValueError(f"{self.name} must be true or false")
            return value.lower() in {"true", "yes", "1"}
        if self.kind is list:
            import shlex

            return shlex.split(value)
        return self.kind(value)


class Module(ABC):
    """Modules provide metadata, options, and a synchronous execution boundary."""

    name: str
    description: str
    options: tuple[Option, ...]
    accepts_targets: bool = False

    def defaults(self) -> dict[str, Any]:
        return {o.name: list(o.default) if o.kind is list else o.default for o in self.options}

    @abstractmethod
    def run(self, settings: dict[str, Any], console: Console) -> int:
        """Execute and return a process-style exit status."""
