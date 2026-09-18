from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import ua,delay,save_evidence

def run(p,t,d,m):
    delay(m); out=d.raw_file(f"wafw00f_{t.domain}.txt")
    r=run_tool("wafw00f",[p.binary_path,"-a",t.url],timeout=30,output_file=out)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"wafw00f.txt")
    return r
plugin=ScannerPlugin("wafw00f","fingerprint",False,"wafw00f","pip install wafw00f",run_override=run,stage="wafw00f")
