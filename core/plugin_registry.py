"""ThreatMap scanner plugin registry and profile loader."""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Any

import yaml

from core.scan_runner import ToolResult, ToolStatus, run_tool
from core.scan_logger import get_logger

log = get_logger("plugins")

Condition = Callable[[dict], bool]

@dataclass
class ScannerPlugin:
    name: str
    category: str
    required: bool
    binary: str
    install_hint: str
    depends_on: list[str] = field(default_factory=list)
    condition: Condition = lambda context: True
    build_command: Optional[Callable[[Any, Any, str], Optional[list[str]]]] = None
    run_override: Optional[Callable[["ScannerPlugin", Any, Any, str], ToolResult]] = None
    parse: Optional[Callable[[Any], dict | list | None]] = None
    timeout: int = 300
    stage: Optional[str] = None
    host_scan: bool = True
    _binary_path: Optional[str] = field(default=None, init=False, repr=False)

    def bind_binary(self, path: Optional[str]) -> None:
        self._binary_path = path

    @property
    def binary_path(self) -> Optional[str]:
        return self._binary_path

    def run(self, target, dirs, mode) -> ToolResult:
        if self.run_override is not None:
            return self.run_override(self, target, dirs, mode)
        if self.build_command is None:
            return ToolResult(tool=self.name, status=ToolStatus.FAILED,
                              error="Plugin has no command builder")
        if not self._binary_path:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              error="not installed")
        cmd = self.build_command(target, dirs, mode)
        if cmd is None:
            return ToolResult(tool=self.name, status=ToolStatus.FAILED,
                              error="Plugin command builder returned no command")
        return run_tool(self.name, cmd, timeout=self.timeout)


class PluginRegistry:
    """Auto-discovers scanner plugins and resolves profile-specific execution order."""

    VALID_CATEGORIES = {"osint", "fingerprint", "port_scan", "web", "vuln"}
    STAGE_ORDER = ("osint", "fingerprint", "port_scan", "web", "vuln")

    def __init__(self, package: str = "plugins", config_path: str | Path = "config/scan_profiles.yaml"):
        self.package = package
        self.config_path = Path(config_path)
        if not self.config_path.is_absolute() and not self.config_path.exists():
            self.config_path = Path(__file__).resolve().parents[1] / self.config_path
        self.plugins: dict[str, ScannerPlugin] = self._discover()
        self._load_profiles()
        self._bind_binaries()

    def _discover(self) -> dict[str, ScannerPlugin]:
        package = importlib.import_module(self.package)
        found: dict[str, ScannerPlugin] = {}
        for modinfo in pkgutil.iter_modules(package.__path__):
            if modinfo.name.startswith("_"):
                continue
            module = importlib.import_module(f"{self.package}.{modinfo.name}")
            plugin = getattr(module, "plugin", None)
            if plugin is None:
                continue
            if not isinstance(plugin, ScannerPlugin):
                raise TypeError(f"{self.package}.{modinfo.name}.plugin is not a ScannerPlugin")
            if plugin.category not in self.VALID_CATEGORIES:
                raise ValueError(f"Invalid category for {plugin.name}: {plugin.category}")
            if plugin.name in found:
                raise ValueError(f"Duplicate scanner plugin: {plugin.name}")
            found[plugin.name] = plugin
        log.info("[plugins] discovered %d scanner plugins", len(found))
        return found

    def _load_profiles(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Scanner profile config not found: {self.config_path}")
        data = yaml.safe_load(self.config_path.read_text()) or {}
        self.profiles = data.get("profiles", {})
        if not self.profiles:
            raise ValueError("No scanner profiles defined")

    def _bind_binaries(self) -> None:
        import os, shutil
        for plugin in self.plugins.values():
            env_key = f"{plugin.binary.upper().replace('-', '_')}_PATH"
            override = os.environ.get(env_key)
            path = override if override and Path(override).is_file() else shutil.which(plugin.binary)
            plugin.bind_binary(path)

    def profile(self, mode: str) -> dict:
        profile = self.profiles.get(mode)
        if profile is None:
            raise ValueError(f"Unknown scan profile: {mode}")
        enabled = profile.get("plugins", {})
        return {"enabled": enabled, "max_workers": int(profile.get("max_workers", 4))}

    def enabled_plugins(self, mode: str, category: Optional[str] = None) -> list[ScannerPlugin]:
        profile = self.profile(mode)
        names = [name for name, value in profile["enabled"].items() if value]
        plugins = [self.plugins[name] for name in names if name in self.plugins]
        if category:
            plugins = [p for p in plugins if p.category == category]
        return self._topological_sort(plugins)

    def _topological_sort(self, plugins: list[ScannerPlugin]) -> list[ScannerPlugin]:
        selected = {p.name: p for p in plugins}
        ordered: list[ScannerPlugin] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                raise ValueError(f"Circular scanner dependency involving {name}")
            visiting.add(name)
            plugin = selected[name]
            for dep in plugin.depends_on:
                if dep in selected:
                    visit(dep)
            visiting.remove(name)
            visited.add(name)
            ordered.append(plugin)

        for p in plugins:
            visit(p.name)
        return ordered

    def should_run(self, plugin: ScannerPlugin, context: dict) -> bool:
        try:
            return bool(plugin.condition(context))
        except Exception as exc:
            log.warning("[plugins] condition failed for %s: %s", plugin.name, exc)
            return False

    def run_category(self, category: str, target, dirs, mode: str, context: dict) -> dict[str, ToolResult]:
        results: dict[str, ToolResult] = {}
        for plugin in self.enabled_plugins(mode, category):
            if not self.should_run(plugin, context):
                continue
            result = plugin.run(target, dirs, mode)
            results[plugin.name] = result
            context.setdefault("results", {})[plugin.name] = result
        return results

    def host_stage_plugins(self, mode: str, stage: str) -> list[ScannerPlugin]:
        """Return enabled host-scan plugins for a legacy-compatible pipeline stage.

        Existing scanners declare their historical stage explicitly. New plugins
        default to their category, so adding a plugin never requires scanner_core edits.
        Discovery-only plugins set host_scan=False and are consumed by ScannerKit.
        """
        enabled = [p for p in self.enabled_plugins(mode) if p.host_scan]
        def effective(p):
            if p.stage: return p.stage
            return {"osint":"whois", "fingerprint":"whatweb", "port_scan":"nmap", "web":"web_tools", "vuln":"nuclei"}[p.category]
        selected = [p for p in enabled if effective(p) == stage]
        return self._topological_sort(selected)

    def run_host_stage(self, mode: str, stage: str, target, dirs, context: dict) -> dict[str, ToolResult]:
        results = {}
        for plugin in self.host_stage_plugins(mode, stage):
            if not self.should_run(plugin, context):
                continue
            results[plugin.name] = plugin.run(target, dirs, mode)
            context.setdefault("results", {})[plugin.name] = results[plugin.name]
        return results

    def validate(self) -> tuple[bool, list[ScannerPlugin]]:
        missing = [p for p in self.plugins.values() if p.required and not p.binary_path]
        return len(missing) == 0, sorted(missing, key=lambda p: p.name)
