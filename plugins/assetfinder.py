from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import save_evidence
def run(p,t,d,m):
    r=run_tool("assetfinder",[p.binary_path,"--subs-only",t.domain],timeout=60)
    if r.ok and r.stdout: Path(d.raw_file("subdomains_af.txt")).write_text(r.stdout); Path(d.evidence/"subdomains_af.txt").write_text(r.stdout)
    return r
plugin=ScannerPlugin("assetfinder","osint",False,"assetfinder","go install github.com/tomnomnom/assetfinder@latest",run_override=run,host_scan=False)
