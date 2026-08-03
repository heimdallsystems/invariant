"""
Checkov-style check registry: subclass BaseCheck, decorate with @register,
and the CLI (cli.py) picks it up automatically via all_checks().
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CheckResult:
    check_id: str
    passed: bool
    severity: Severity
    file_path: str
    message: str
    counterexample: Optional[dict] = field(default=None)


class BaseCheck:
    check_id: str = ""
    name: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""

    def applies_to(self, file_path: str) -> bool:
        """Whether this check should run against the given candidate path."""
        return True

    def run(self, reference: dict, candidate: dict, file_path: str) -> CheckResult:
        raise NotImplementedError


_REGISTRY: dict[str, type[BaseCheck]] = {}


def register(check_cls: type[BaseCheck]) -> type[BaseCheck]:
    if not check_cls.check_id:
        raise ValueError(f"{check_cls.__name__} must set check_id before registering")
    _REGISTRY[check_cls.check_id] = check_cls
    return check_cls


def all_checks() -> dict[str, type[BaseCheck]]:
    return dict(_REGISTRY)
