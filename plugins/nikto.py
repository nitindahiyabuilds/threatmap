from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import ua,delay,save_evidence
def run(p,t,d,m):
    delay(m); out=d.raw_file(f"nikto_{t.domain}.txt"); maxtime="5m" if m=="aggressive" else "3m"
    r=run_tool("nikto",[p.binary_path,"-h",t.url,"-useragent",ua(),"-output",out,"-maxtime",maxtime,"-nointeractive"],timeout=360)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"nikto.txt")
    return r
plugin=ScannerPlugin("nikto","web",True,"nikto","sudo apt install -y nikto",depends_on=["nmap"],run_override=run,stage="web_tools")
