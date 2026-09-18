from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import save_evidence
def condition(c): return bool(c.get("open_ports",[])) or str(c.get("host","")).startswith("http")
def run(p,t,d,m):
    out=d.raw_file(f"nuclei_{t.domain}.txt")
    if m=="aggressive": cmd=[p.binary_path,"-u",t.url,"-o",out,"-silent","-timeout","10","-rate-limit","150","-bulk-size","30","-c","30"]; timeout=900
    else: cmd=[p.binary_path,"-u",t.url,"-o",out,"-silent","-severity","critical,high,medium","-tags","cve,exposure,misconfig,default-login,takeover","-timeout","8","-rate-limit","80","-bulk-size","20","-c","20"]; timeout=300
    r=run_tool("nuclei",cmd,timeout=timeout)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"nuclei.txt")
    return r
plugin=ScannerPlugin("nuclei","vuln",False,"nuclei","go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",depends_on=["nmap"],condition=condition,run_override=run,stage="nuclei")
