"""ThreatMap scanner plugin registry and profile loader."""

from __future__ import annotations

import importlib
import os
import pkgutil
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from core.scan_logger import get_logger
from core.scan_runner import ToolResult, ToolStatus, run_tool

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

    build_command: Optional[
        Callable[[Any, Any, str], Optional[list[str]]]
    ] = None

    run_override: Optional[
        Callable[["ScannerPlugin", Any, Any, str], ToolResult]
    ] = None

    parse: Optional[Callable[[Any], dict | list | None]] = None

    timeout: int = 300

    # Compatibility metadata.
    # The orchestrator no longer hardcodes these values.
    stage: Optional[str] = None

    # False = discovery-only plugin used by ScannerKit.
    host_scan: bool = True

    _binary_path: Optional[str] = field(
        default=None,
        init=False,
        repr=False,
    )

    def bind_binary(self, path: Optional[str]) -> None:
        self._binary_path = path

    @property
    def binary_path(self) -> Optional[str]:
        return self._binary_path

    def run(self, target, dirs, mode) -> ToolResult:
        if self.run_override is not None:
            return self.run_override(self, target, dirs, mode)

        if self.build_command is None:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error="Plugin has no command builder",
            )

        if not self._binary_path:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                error="not installed",
            )

        cmd = self.build_command(target, dirs, mode)

        if cmd is None:
            return ToolResult(
                tool=self.name,
                status=ToolStatus.FAILED,
                error="Plugin command builder returned no command",
            )

        return run_tool(
            self.name,
            cmd,
            timeout=self.timeout,
        )


class PluginRegistry:
    """
    Discovers scanner plugins, loads scan profiles, resolves binaries,
    validates dependencies, and produces the execution plan.
    """

    VALID_CATEGORIES = {
        "osint",
        "fingerprint",
        "port_scan",
        "web",
        "vuln",
    }

    CATEGORY_ORDER = (
        "osint",
        "fingerprint",
        "port_scan",
        "web",
        "vuln",
    )

    # Public result compatibility:
    #
    # Several web plugins historically appeared underneath one
    # `web_tools` pipeline stage. We preserve that external shape while
    # allowing the internal implementation to be plugin-based.
    DEFAULT_STAGE_BY_CATEGORY = {
        "osint": None,
        "fingerprint": None,
        "port_scan": None,
        "web": "web_tools",
        "vuln": None,
    }

    def __init__(
        self,
        package: str = "plugins",
        config_path: str | Path = "config/scan_profiles.yaml",
    ):
        self.package = package

        self.config_path = Path(config_path)

        if (
            not self.config_path.is_absolute()
            and not self.config_path.exists()
        ):
            self.config_path = (
                Path(__file__).resolve().parents[1]
                / self.config_path
            )

        self.plugins: dict[str, ScannerPlugin] = self._discover()

        self._validate_plugin_dependencies()

        self._load_profiles()
        self._bind_binaries()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discover(self) -> dict[str, ScannerPlugin]:
        package = importlib.import_module(self.package)

        found: dict[str, ScannerPlugin] = {}

        for modinfo in pkgutil.iter_modules(package.__path__):
            if modinfo.name.startswith("_"):
                continue

            module = importlib.import_module(
                f"{self.package}.{modinfo.name}"
            )

            plugin = getattr(module, "plugin", None)

            if plugin is None:
                continue

            if not isinstance(plugin, ScannerPlugin):
                raise TypeError(
                    f"{self.package}.{modinfo.name}.plugin "
                    "is not a ScannerPlugin"
                )

            if plugin.category not in self.VALID_CATEGORIES:
                raise ValueError(
                    f"Invalid category for {plugin.name}: "
                    f"{plugin.category}"
                )

            if plugin.name in found:
                raise ValueError(
                    f"Duplicate scanner plugin: {plugin.name}"
                )

            found[plugin.name] = plugin

        log.info(
            "[plugins] discovered %d scanner plugins",
            len(found),
        )

        return found

    def _validate_plugin_dependencies(self) -> None:
        for plugin in self.plugins.values():
            for dependency in plugin.depends_on:
                if dependency not in self.plugins:
                    raise ValueError(
                        f"Plugin {plugin.name} depends on unknown "
                        f"plugin: {dependency}"
                    )

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def _load_profiles(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Scanner profile config not found: "
                f"{self.config_path}"
            )

        data = yaml.safe_load(
            self.config_path.read_text()
        ) or {}

        self.profiles = data.get("profiles", {})

        if not self.profiles:
            raise ValueError(
                "No scanner profiles defined"
            )

    def profile(self, mode: str) -> dict:
        profile = self.profiles.get(mode)

        if profile is None:
            raise ValueError(
                f"Unknown scan profile: {mode}"
            )

        enabled = profile.get("plugins", {})

        return {
            "enabled": enabled,
            "max_workers": int(
                profile.get("max_workers", 4)
            ),
        }

    # ------------------------------------------------------------------
    # Binary resolution
    # ------------------------------------------------------------------

    def _bind_binaries(self) -> None:
        for plugin in self.plugins.values():
            env_key = (
                f"{plugin.binary.upper().replace('-', '_')}_PATH"
            )

            override = os.environ.get(env_key)

            if (
                override
                and Path(override).is_file()
            ):
                path = override
            else:
                path = shutil.which(plugin.binary)

            plugin.bind_binary(path)

    # ------------------------------------------------------------------
    # Profile selection
    # ------------------------------------------------------------------

    def enabled_plugins(
        self,
        mode: str,
        category: Optional[str] = None,
    ) -> list[ScannerPlugin]:
        profile = self.profile(mode)

        names = [
            name
            for name, enabled
            in profile["enabled"].items()
            if enabled
        ]

        plugins = [
            self.plugins[name]
            for name in names
            if name in self.plugins
        ]

        if category is not None:
            plugins = [
                plugin
                for plugin in plugins
                if plugin.category == category
            ]

        return self._topological_sort(plugins)

    # ------------------------------------------------------------------
    # Dependency resolution
    # ------------------------------------------------------------------

    def _topological_sort(
        self,
        plugins: list[ScannerPlugin],
    ) -> list[ScannerPlugin]:
        selected = {
            plugin.name: plugin
            for plugin in plugins
        }

        ordered: list[ScannerPlugin] = []

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return

            if name in visiting:
                raise ValueError(
                    f"Circular scanner dependency involving {name}"
                )

            plugin = selected[name]

            visiting.add(name)

            for dependency in plugin.depends_on:
                if dependency in selected:
                    visit(dependency)

            visiting.remove(name)
            visited.add(name)

            ordered.append(plugin)

        for plugin in plugins:
            visit(plugin.name)

        return ordered

    def execution_plan(
        self,
        mode: str,
    ) -> list[ScannerPlugin]:
        """
        Return all enabled host-scan plugins in dependency-safe order.

        Discovery-only plugins such as subfinder, assetfinder and httpx
        are excluded because ScannerKit owns that workflow.
        """

        enabled = [
            plugin
            for plugin in self.enabled_plugins(mode)
            if plugin.host_scan
        ]

        return self._topological_sort_with_dependencies(
            enabled,
            mode,
    )

    def _topological_sort_with_dependencies(
        self,
        plugins: list[ScannerPlugin],
        mode: str,
    ) -> list[ScannerPlugin]:
        """
        Topologically sort the complete enabled dependency graph.

        Unlike the older implementation, dependencies are included in
        the graph even when they belong to another category.
        """

        selected = {
            plugin.name: plugin
            for plugin in plugins
        }

        # Include enabled dependencies recursively.
        expanded = dict(selected)

        changed = True

        while changed:
            changed = False

            for plugin in list(expanded.values()):
                for dependency in plugin.depends_on:
                    dependency_plugin = self.plugins.get(
                        dependency
                    )

                    if dependency_plugin is None:
                        raise ValueError(
                            f"Unknown dependency: {dependency}"
                        )

                    if not dependency_plugin.host_scan:
                        raise ValueError(
                            f"Host plugin {plugin.name} depends on "
                            f"discovery-only plugin {dependency}"
                        )

                    profile_enabled = dependency in {
            name
                for name, enabled
                in self.profile(mode)["enabled"].items()
                if enabled
            }

                    if not profile_enabled:
                        raise ValueError(
                            f"Plugin {plugin.name} depends on "
                            f"disabled plugin {dependency}"
                        )

                    if dependency not in expanded:
                        expanded[dependency] = dependency_plugin
                        changed = True

        visiting: set[str] = set()
        visited: set[str] = set()
        ordered: list[ScannerPlugin] = []

        def visit(name: str) -> None:
            if name in visited:
                return

            if name in visiting:
                raise ValueError(
                    f"Circular scanner dependency involving {name}"
                )

            visiting.add(name)

            plugin = expanded[name]

            for dependency in plugin.depends_on:
                if dependency in expanded:
                    visit(dependency)

            visiting.remove(name)
            visited.add(name)
            ordered.append(plugin)

        for plugin in expanded.values():
            visit(plugin.name)

        # Preserve the intended broad scanner phases when there are
        # independent plugins while still respecting dependencies.
        category_index = {
            category: index
            for index, category
            in enumerate(self.CATEGORY_ORDER)
        }

        position = {
            plugin.name: index
            for index, plugin
            in enumerate(ordered)
        }

        # Stable category ordering among dependency-independent nodes.
        ordered.sort(
            key=lambda plugin: (
                category_index.get(
                    plugin.category,
                    len(category_index),
                ),
                position[plugin.name],
            )
        )

        # Sorting by category can disturb a dependency edge, so validate
        # the final order and fall back to the pure topological result if
        # necessary.
        indexes = {
            plugin.name: index
            for index, plugin
            in enumerate(ordered)
        }

        for plugin in ordered:
            for dependency in plugin.depends_on:
                if (
                    dependency in indexes
                    and indexes[dependency]
                    > indexes[plugin.name]
                ):
                    return self._pure_topological_sort(
                        expanded
                    )

        return ordered

    def _pure_topological_sort(
        self,
        plugins: dict[str, ScannerPlugin],
    ) -> list[ScannerPlugin]:
        ordered: list[ScannerPlugin] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return

            if name in visiting:
                raise ValueError(
                    f"Circular scanner dependency involving {name}"
                )

            visiting.add(name)

            for dependency in plugins[name].depends_on:
                if dependency in plugins:
                    visit(dependency)

            visiting.remove(name)
            visited.add(name)
            ordered.append(plugins[name])

        for name in plugins:
            visit(name)

        return ordered

    # ------------------------------------------------------------------
    # Runtime conditions
    # ------------------------------------------------------------------

    def should_run(
        self,
        plugin: ScannerPlugin,
        context: dict,
    ) -> bool:
        try:
            return bool(
                plugin.condition(context)
            )
        except Exception as exc:
            log.warning(
                "[plugins] condition failed for %s: %s",
                plugin.name,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Stage compatibility
    # ------------------------------------------------------------------

    def effective_stage(
        self,
        plugin: ScannerPlugin,
    ) -> str:
        """
        Map a plugin to the externally visible pipeline stage.

        Explicit stage metadata wins. Otherwise use category defaults.
        """

        if plugin.stage:
            return plugin.stage

        default = self.DEFAULT_STAGE_BY_CATEGORY.get(
            plugin.category
        )

        if default is None:
            return plugin.name

        return default

    def execution_stages(
        self,
        mode: str,
    ) -> list[tuple[str, list[ScannerPlugin]]]:
        """
        Build the execution plan grouped by legacy-compatible stage.

        Ordering is determined by the plugin dependency graph.
        scanner_core does not contain scanner names or stage names.
        """

        self._current_mode = mode

        plan = self.execution_plan(mode)

        stages: list[tuple[str, list[ScannerPlugin]]] = []

        for plugin in plan:
            stage = self.effective_stage(plugin)

            if not stages or stages[-1][0] != stage:
                stages.append((stage, [plugin]))
            else:
                stages[-1][1].append(plugin)

        return stages

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> tuple[bool, list[ScannerPlugin]]:
        missing = [
            plugin
            for plugin in self.plugins.values()
            if plugin.required and not plugin.binary_path
        ]

        return (
            len(missing) == 0,
            sorted(
                missing,
                key=lambda plugin: plugin.name,
            ),
        )

    def run_host_stage(self, stage, target, dirs, mode="balanced", context=None):
        """Run all enabled plugins belonging to a scanner stage."""
        context = dict(context or {})
        results = {}

        for plugin in self.execution_plan(mode):
            if plugin.stage != stage:
                continue

            if not self.should_run(plugin, context):
                continue

            results[plugin.name] = plugin.run(target, dirs, mode)

        return results
