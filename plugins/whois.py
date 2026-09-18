from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import save_evidence

def run(p,t,d,m):
    out=d.raw_file(f"whois_{t.domain}.txt")
    r=run_tool("whois", [p.binary_path,t.domain], timeout=20, output_file=out)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"whois.txt")
    return r
plugin=ScannerPlugin("whois","osint",True,"whois","sudo apt install -y whois",run_override=run,stage="whois")
