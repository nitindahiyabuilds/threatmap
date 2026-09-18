from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import save_evidence
def run(p,t,d,m):
    out=d.raw_file("subdomains.txt"); r=run_tool("subfinder",[p.binary_path,"-d",t.domain,"-silent","-o",out],timeout=120)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"subdomains.txt")
    return r
plugin=ScannerPlugin("subfinder","osint",False,"subfinder","go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",run_override=run,host_scan=False)
