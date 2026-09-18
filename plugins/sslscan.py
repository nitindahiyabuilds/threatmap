from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import save_evidence
def condition(c): return "443" in set(c.get("open_ports",[])) or str(c.get("host","")).startswith("https")
def run(p,t,d,m):
    out=d.raw_file(f"sslscan_{t.domain}.txt"); r=run_tool("sslscan",[p.binary_path,"--no-colour",t.domain],timeout=60,output_file=out)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"sslscan.txt")
    return r
plugin=ScannerPlugin("sslscan","web",True,"sslscan","sudo apt install -y sslscan",depends_on=["nmap"],condition=condition,run_override=run,stage="web_tools")
