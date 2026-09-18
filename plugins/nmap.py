import xml.etree.ElementTree as ET
from pathlib import Path
from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool
from core.scan_runner import ToolStatus
from core.scan_logger import get_logger
from ._common import delay
log=get_logger("scanner")

def run(p,t,d,m):
    delay(m); out=d.raw_file(f"nmap_{t.domain}.xml")
    if m=="aggressive":
        cmd=[p.binary_path,"-sV","-sC","-A","-Pn","-p-","--min-rate","2000","--max-retries","1","-T4","-oX",out,t.domain]
        fallback=[p.binary_path,"-sV","-sC","-Pn","--top-ports","5000","-T4","-oX",out,t.domain]; timeout=900
    else:
        cmd=[p.binary_path,"-sV","-sC","-Pn","--top-ports","1000","-T4","--max-retries","1","-oX",out,t.domain]
        fallback=[p.binary_path,"-Pn","--top-ports","200","-T3","-oX",out,t.domain]; timeout=300
    r=run_tool("nmap",cmd,timeout=timeout)
    if r.status==ToolStatus.TIMEOUT:
        log.warning("[nmap] primary timed out, running fallback")
        r=run_tool("nmap:fallback",fallback,timeout=timeout//2)
    if r.ok and r.stdout: Path(d.evidence/"nmap.txt").write_text(r.stdout)
    return r

def parse(path):
    try: tree=ET.parse(path)
    except Exception as exc:
        log.warning("[nmap:parse] %s — %s",path,exc); return []
    results=[]
    for port in tree.getroot().findall(".//port"):
        state=port.find("state")
        if state is None or state.get("state")!="open": continue
        svc=port.find("service"); parts=[]
        if svc is not None:
            for a in ["product","version","extrainfo"]:
                v=svc.get(a,"")
                if v: parts.append(v)
        results.append({"port":port.get("portid"),"protocol":port.get("protocol","tcp"),"state":"open","service":svc.get("name","unknown") if svc is not None else "unknown","version":" ".join(parts),"cpe":[c.text for c in port.findall(".//cpe") if c.text]})
    log.debug("[nmap:parse] %d open ports from %s",len(results),path); return results
plugin=ScannerPlugin("nmap","port_scan",True,"nmap","sudo apt install -y nmap",run_override=run,parse=parse,stage="nmap")
