from core.plugin_registry import ScannerPlugin
from core.scan_runner import run_tool,ToolResult,ToolStatus
from pathlib import Path
from ._common import ua,delay,save_evidence
def run(p,t,d,m):
    delay(m); ag=["/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt","/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt","/usr/share/wordlists/dirb/big.txt"]; ba=["/usr/share/seclists/Discovery/Web-Content/common.txt","/usr/share/wordlists/dirb/common.txt","/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"]; wl=next((x for x in (ag if m=="aggressive" else ba) if Path(x).exists()),None)
    if not wl: return ToolResult("gobuster",ToolStatus.SKIPPED,error="no wordlist found")
    out=d.raw_file(f"gobuster_{t.domain}.txt"); threads="80" if m=="aggressive" else "50"
    r=run_tool("gobuster",[p.binary_path,"dir","-u",t.url,"-w",wl,"-a",ua(),"-o",out,"-b","404,301,302","-t",threads,"--timeout","8s","-q"],timeout=300)
    if r.ok and Path(out).exists(): save_evidence(out,d.evidence/"gobuster.txt")
    return r
plugin=ScannerPlugin("gobuster","web",True,"gobuster","sudo apt install -y gobuster",depends_on=["nmap"],run_override=run,stage="web_tools")
