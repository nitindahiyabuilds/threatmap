import random
import time
from pathlib import Path
from core.scan_runner import ToolResult, ToolStatus, run_tool

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:125.0) Gecko/20100101 Firefox/125.0",
]

def ua(): return random.choice(USER_AGENTS)
def delay(mode): time.sleep(random.uniform(0.5,1.5) if mode == "balanced" else random.uniform(0.1,0.5))
def save_evidence(raw_path, evidence_path):
    p=Path(raw_path)
    if p.exists(): Path(evidence_path).write_text(p.read_text())

def skip(name, error="not installed"):
    return ToolResult(tool=name, status=ToolStatus.SKIPPED, error=error)
