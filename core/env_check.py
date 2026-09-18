from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.plugin_registry import PluginRegistry
from core.scan_logger import get_logger


log = get_logger("env")


@dataclass(frozen=True)
class ToolDef:
    name: str
    required: bool
    install: str
    verify: str = ""
    version_flag: str = "--version"


def _load_tool_defs() -> list[ToolDef]:
    registry = PluginRegistry()

    v1_order = [
        "nmap",
        "nikto",
        "gobuster",
        "sslscan",
        "whatweb",
        "curl",
        "whois",
        "dig",
        "subfinder",
        "httpx",
        "assetfinder",
        "nuclei",
        "wafw00f",
    ]

    return [
        ToolDef(
            name=name,
            required=registry.plugins[name].required,
            install=registry.plugins[name].install_hint,
        )
        for name in v1_order
        if name in registry.plugins
    ]


TOOLS = _load_tool_defs()


class ToolRegistry:
    def __init__(self) -> None:
        self._paths: dict[str, Optional[str]] = {}
        self._checked = False

    def validate(self) -> tuple[bool, list[ToolDef]]:
        missing: list[ToolDef] = []

        for tool in TOOLS:
            path = self._resolve(tool.name)

            if path:
                self._paths[tool.name] = path
            elif tool.required:
                missing.append(tool)

        self._checked = True

        return len(missing) == 0, missing

    def get(self, name: str) -> Optional[str]:
        if name not in self._paths:
            self._paths[name] = self._resolve(name)

        return self._paths[name]

    def available(self, name: str) -> bool:
        return self.get(name) is not None

    def print_install_guide(self, missing: list[ToolDef]) -> None:
        if not missing:
            return

        print("\nMissing required tools:")

        for tool in missing:
            print(f"  {tool.name}: {tool.install}")

        print()

    def print_status_table(self) -> None:
        print("\nTool status:")

        for tool in TOOLS:
            path = self.get(tool.name)

            if path:
                status = "OK"
                location = path
            else:
                status = "MISSING"
                location = "-"

            print(
                f"  {tool.name:<12} "
                f"{status:<8} "
                f"{location}"
            )

        print()

    def _resolve(self, name: str) -> Optional[str]:
        env_name = f"{name.upper()}_PATH"
        override = os.environ.get(env_name)

        if override:
            path = Path(override).expanduser()

            if path.is_file() and os.access(path, os.X_OK):
                return str(path)

            get_logger(__name__).warning(
                "Configured %s=%s is not a valid executable",
                env_name,
                override,
            )

        return shutil.which(name)


@dataclass
class ScanDirs:
    root: Path
    evidence: Path = field(init=False)
    raw: Path = field(init=False)
    reports: Path = field(init=False)
    logs: Path = field(init=False)

    def __post_init__(self) -> None:
        self.evidence = self.root / "evidence"
        self.raw = self.root / "raw"
        self.reports = self.root / "reports"
        self.logs = self.root / "logs"

        for directory in (
            self.root,
            self.evidence,
            self.raw,
            self.reports,
            self.logs,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def create(
        cls,
        base_dir: Path = None,
        target: str = "",
        base: str = None,
    ) -> "ScanDirs":
        if base_dir is None:
            if base is None:
                raise TypeError("ScanDirs.create() requires base or base_dir")
            base_dir = Path(base)
        elif base is not None:
            raise TypeError("provide only one of base or base_dir")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        slug = cls._safe_slug(target)

        root = base_dir / f"{slug}_{timestamp}"

        return cls(root=root)

    @property
    def report_dir(self) -> str:
        return str(self.reports)

    @property
    def raw_dir(self) -> str:
        return str(self.raw)

    @property
    def log_file(self) -> str:
        return str(self.logs / "scan.log")

    def raw_file(self, name: str) -> str:
        return str(self.raw / name)

    @staticmethod
    def _safe_slug(value: str):
        safe = "".join(
            character
            if character.isalnum() or character in "-_."
            else "_"
            for character in value
        )

        safe = safe.strip("._")

        return safe or "target"
