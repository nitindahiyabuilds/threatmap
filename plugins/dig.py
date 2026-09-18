from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool, ToolResult, ToolStatus
from pathlib import Path

def run(p,t,d,m):
    if not p.binary_path: return ToolResult("dig",ToolStatus.SKIPPED,error="not installed")
    out=d.raw_file(f"dig_{t.domain}.txt"); combined=[]
    for typ in ["A","AAAA","MX","NS","TXT","SOA"]:
        r=run_tool(f"dig:{typ}",[p.binary_path,t.domain,typ,"+short"],timeout=10)
        combined.append(f"\n=== {typ} ===\n{r.stdout or '(none)'}")
    text="\n".join(combined); Path(out).write_text(text); Path(d.evidence/"dig.txt").write_text(text)
    return ToolResult("dig",ToolStatus.SUCCESS,stdout=text)
plugin=ScannerPlugin("dig","osint",True,"dig","sudo apt install -y dnsutils",run_override=run,stage="dig")
