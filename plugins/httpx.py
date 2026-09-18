from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool,ToolResult,ToolStatus
from pathlib import Path
def run(p,t,d,m):
    subs=d.raw_file("subdomains_all.txt")
    if not p.binary_path or not Path(subs).exists(): return ToolResult("httpx",ToolStatus.SKIPPED,error="not installed or no subs file")
    return run_tool("httpx",[p.binary_path,"-l",subs,"-silent","-o",d.raw_file("live_hosts.txt")],timeout=120)
plugin=ScannerPlugin("httpx","osint",False,"httpx","go install github.com/projectdiscovery/httpx/cmd/httpx@latest",run_override=run,host_scan=False)
