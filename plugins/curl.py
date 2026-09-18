from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from pathlib import Path
from ._common import ua,save_evidence
def run(p,t,d,m):
    out=d.raw_file(f"curl_headers_{t.domain}.txt"); r=run_tool("curl",[p.binary_path,"-s","-I","-L","--max-redirs","5","-A",ua(),"--connect-timeout","8","--max-time","15",t.url],timeout=20,output_file=out)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"curl_headers.txt")
    return r
plugin=ScannerPlugin("curl","web",True,"curl","sudo apt install -y curl",depends_on=["nmap"],run_override=run,stage="web_tools")
