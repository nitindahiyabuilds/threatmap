from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import ua,delay,save_evidence

def run(p,t,d,m):
    delay(m); out=d.raw_file(f"whatweb_{t.domain}.json")
    r=run_tool("whatweb",[p.binary_path,"-v","--user-agent",ua(),f"--log-json={out}",t.url],timeout=60)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"whatweb.json")
    return r
plugin=ScannerPlugin("whatweb","fingerprint",True,"whatweb","sudo apt install -y whatweb",run_override=run,stage="whatweb")
