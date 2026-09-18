"""ThreatMap scanner orchestration backed by the plugin registry."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.env_check import ToolRegistry, ScanDirs
from core.scan_runner import ToolResult, ToolStatus, ExecutionPipeline
from core.plugin_registry import PluginRegistry
from core.scan_logger import get_logger


log = get_logger("scanner")

MODE_BALANCED = "balanced"
MODE_AGGRESSIVE = "aggressive"

_registry = ToolRegistry()


def _failure_message(tool, status, error):
    reason = "execution error"

    if status == ToolStatus.TIMEOUT:
        reason = "timed out"
    elif status == ToolStatus.SKIPPED:
        reason = "not available in environment"
    elif error:
        reason = error

    impact = "this scan area may have reduced coverage"

    if tool == "nmap":
        impact = "port and service visibility may be incomplete"
    elif tool in {
        "nuclei",
        "nikto",
        "gobuster",
        "whatweb",
        "wafw00f",
    }:
        impact = "web vulnerability visibility may be partial"
    elif tool in {
        "whois",
        "dig",
        "subfinder",
        "assetfinder",
        "httpx",
    }:
        impact = "discovery scope may be reduced"

    return f"{tool} failed ({reason}); {impact}"


class Target:
    def __init__(self, raw):
        self.raw = raw.strip()

        clean = (
            self.raw
            .replace("https://", "")
            .replace("http://", "")
        )

        self.domain = (
            clean
            .split("/")[0]
            .split("?")[0]
        )

        self.url = f"https://{self.domain}"

    def __repr__(self):
        return f"Target({self.domain})"


def validate_environment():
    return _registry.validate()


class ParallelOrchestrator:
    def __init__(self, mode=MODE_BALANCED):
        self.mode = mode
        self.registry = PluginRegistry()
        self.max_workers = self.registry.profile(mode)["max_workers"]

        log.info(
            "[orchestrator] mode=%s workers=%d",
            mode,
            self.max_workers,
        )

    def run_scan_suite(self, hosts, dirs):
        results = {}

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as ex:
            fmap = {
                ex.submit(
                    self.scan_host,
                    host,
                    dirs,
                ): host
                for host in hosts
            }

            for future in as_completed(fmap):
                host = fmap[future]

                try:
                    results[host] = future.result()

                except Exception as exc:
                    log.error(
                        "[orchestrator] host %s failed: %s",
                        host,
                        exc,
                    )

                    results[host] = {
                        "host": host,
                        "error": str(exc),
                        "nmap": [],
                        "open_ports": [],
                    }

        return results

    def scan_host(self, host, dirs):
        return self._scan_single_host(host, dirs)

    def _scan_single_host(self, host, dirs):
        target = Target(host)

        log.info(
            "━━━ scanning: %s [%s] ━━━",
            host,
            self.mode,
        )

        result = {
            "host": host,
            "nmap": [],
            "open_ports": [],
            "error": None,
            "tool_status": {},
        }

        pipeline = ExecutionPipeline(
            name=target.domain
        )

        def add_stage(stage_name):
            def execute():
                context = {
                    "host": host,
                    "target": target,
                    "open_ports": result.get(
                        "open_ports",
                        [],
                    ),
                    "results": {},
                }

                runs = self.registry.run_host_stage(
                    stage_name,
                    target,
                    dirs,
                    self.mode,
                    context,
                )

                if (
                    stage_name == "nmap"
                    and "nmap" in runs
                ):
                    nmap = runs["nmap"]
                    parsed = []

                    xml = str(dirs.raw / f"nmap_{target.domain}.xml")

                    if nmap.status != ToolStatus.FAILED:
                        parser = self.registry.plugins[
                            "nmap"
                        ].parse

                        parsed = (
                            parser(xml)
                            if parser
                            else []
                        )

                    result["nmap"] = parsed

                    result["open_ports"] = [
                        item["port"]
                        for item in parsed
                    ]

                if not runs:
                    return ToolResult(
                        stage_name,
                        ToolStatus.SKIPPED,
                        error="no enabled plugins",
                    )

                statuses = [
                    run.status
                    for run in runs.values()
                ]

                if stage_name == "web_tools":
                    return ToolResult(
                        "web_tools",
                        ToolStatus.SUCCESS,
                    )

                if any(
                    status == ToolStatus.TIMEOUT
                    for status in statuses
                ):
                    status = ToolStatus.TIMEOUT

                elif any(
                    status == ToolStatus.FAILED
                    for status in statuses
                ):
                    status = ToolStatus.FAILED

                elif all(
                    status == ToolStatus.SKIPPED
                    for status in statuses
                ):
                    status = ToolStatus.SKIPPED

                else:
                    status = ToolStatus.SUCCESS

                return ToolResult(
                    stage_name,
                    status,
                )

            return execute

        # Build host stages from the plugin registry.
        plan = self.registry.execution_plan(
            self.mode
        )

        stages = []
        seen = set()

        for plugin in plan:
            stage = plugin.stage or plugin.name

            if stage in seen:
                continue

            seen.add(stage)
            stages.append(stage)

        # web_tools is a V1-compatible grouped stage.
        if "web_tools" in stages:
            stages.remove("web_tools")

        # nuclei remains a separate V1-compatible stage.
        if "nuclei" in stages:
            stages.remove("nuclei")

        for stage in stages:
            pipeline.add(
                stage,
                add_stage(stage),
            )

        pipeline.add(
            "web_tools",
            lambda: self._run_web_stage(
                target,
                dirs,
                result,
                host,
            ),
        )

        if "nuclei" in {
            plugin.name
            for plugin in plan
        }:
            pipeline.add(
                "nuclei",
                add_stage("nuclei"),
            )

        tool_results = pipeline.run()

        result["tool_status"] = {
            name: tool_result.status.value
            for name, tool_result
            in tool_results.items()
        }

        for name, tool_result in tool_results.items():
            if tool_result.status in {
                ToolStatus.FAILED,
                ToolStatus.TIMEOUT,
                ToolStatus.SKIPPED,
            }:
                log.warning(
                    "[%s] %s",
                    target.domain,
                    _failure_message(
                        name,
                        tool_result.status,
                        tool_result.error,
                    ),
                )

        log.info(
            "━━━ done: %s  ports=%s ━━━",
            host,
            result["open_ports"] or "none",
        )

        return result

    def _run_named_stage(
        self,
        name,
        target,
        dirs,
        result,
    ):
        plugin = self.registry.plugins.get(name)

        if not plugin:
            return ToolResult(
                name,
                ToolStatus.SKIPPED,
                error="plugin not found",
            )

        enabled = any(
            item.name == name
            for item in self.registry.enabled_plugins(
                self.mode,
                plugin.category,
            )
        )

        if not enabled:
            return ToolResult(
                name,
                ToolStatus.SKIPPED,
                error="disabled by profile",
            )

        context = {
            "host": target.raw,
            "target": target,
            "open_ports": result.get(
                "open_ports",
                [],
            ),
            "results": {},
        }

        if not self.registry.should_run(
            plugin,
            context,
        ):
            return ToolResult(
                name,
                ToolStatus.SKIPPED,
                error="condition not met",
            )

        return plugin.run(
            target,
            dirs,
            self.mode,
        )

    def _run_web_stage(
        self,
        target,
        dirs,
        result,
        host,
    ):
        open_ports = set(
            result.get(
                "open_ports",
                [],
            )
        )

        has_web = (
            bool(
                open_ports
                & {
                    "80",
                    "443",
                    "8080",
                    "8443",
                    "8000",
                    "8888",
                }
            )
            or host.startswith("http")
        )

        if not has_web:
            return ToolResult(
                "web_tools",
                ToolStatus.SKIPPED,
                error="no web ports detected",
            )

        context = {
            "host": host,
            "target": target,
            "open_ports": list(open_ports),
            "results": {},
        }

        runs = self.registry.run_host_stage(
            self.mode,
            "web_tools",
            target,
            dirs,
            context,
        )

        if not runs:
            return ToolResult(
                "web_tools",
                ToolStatus.SKIPPED,
                error="no enabled web plugins",
            )

        return ToolResult(
            "web_tools",
            ToolStatus.SUCCESS,
        )


class ScannerKit:
    @staticmethod
    def discover_subdomains(target, dirs):
        subs = set()
        registry = PluginRegistry()

        with ThreadPoolExecutor(
            max_workers=2
        ) as ex:
            subfinder_future = ex.submit(
                registry.plugins["subfinder"].run,
                target,
                dirs,
                MODE_BALANCED,
            )

            assetfinder_future = ex.submit(
                registry.plugins["assetfinder"].run,
                target,
                dirs,
                MODE_BALANCED,
            )

            subfinder_result = subfinder_future.result()
            assetfinder_result = assetfinder_future.result()

        if (
            subfinder_result.ok
            and Path(
                str(dirs.raw / "subdomains.txt")
            ).exists()
        ):
            subs.update(
                line.strip()
                for line in Path(
                    str(dirs.raw / "subdomains.txt")
                ).read_text().splitlines()
                if line.strip()
            )

        if (
            assetfinder_result.ok
            and assetfinder_result.stdout
        ):
            subs.update(
                line.strip()
                for line
                in assetfinder_result.stdout.splitlines()
                if (
                    line.strip()
                    and target.domain in line
                )
            )

        if subs:
            Path(
                str(dirs.raw / "subdomains_all.txt")
            ).write_text(
                "\n".join(sorted(subs))
            )

        log.info(
            "[discovery] %d unique subdomains found",
            len(subs),
        )

        return sorted(subs)

    @staticmethod
    def filter_live_hosts(subs, dirs):
        if not subs:
            return []

        registry = PluginRegistry()
        plugin = registry.plugins["httpx"]

        result = plugin.run(
            Target(""),
            dirs,
            MODE_BALANCED,
        )

        if not result.ok:
            return []

        live_file = str(dirs.raw / "live_hosts.txt")

        if not Path(live_file).exists():
            return []

        hosts = [
            line.strip()
            for line
            in Path(live_file).read_text().splitlines()
            if line.strip()
        ]

        log.info(
            "[discovery] %d live hosts after httpx",
            len(hosts),
        )

        return hosts
