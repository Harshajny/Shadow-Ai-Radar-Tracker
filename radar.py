"""
Shadow AI Radar — Layer 1: running-process detection.
Privacy: reads only the process list (names). No file contents, no secrets.
"""
import psutil

# Signature table from DESIGN_NOTES.md §2. Matched case-insensitively as substrings.
# (tool name, substring to look for, category, risk tier)
AI_SIGNATURES = [
    ("Claude Desktop",  "claude",      "chat_app",   "low"),
    ("ChatGPT Desktop", "chatgpt",     "chat_app",   "low"),
    ("Cursor",          "cursor",      "code_agent", "medium"),
    ("Windsurf",        "windsurf",    "code_agent", "medium"),
    ("Perplexity",      "perplexity",  "chat_app",   "low"),
    ("Ollama",          "ollama",      "local_llm",  "medium"),
    ("LM Studio",       "lm studio",   "local_llm",  "medium"),
]

def scan_processes():
    """Return a list of detected AI tools currently running."""
    detections = []
    seen = set()  # avoid duplicate hits for the same tool

    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue  # process vanished or we can't see it — skip safely

        for tool, needle, category, risk in AI_SIGNATURES:
            if needle in name and tool not in seen:
                seen.add(tool)
                detections.append({
                    "tool": tool,
                    "category": category,
                    "risk": risk,
                    "detail": f"process: {proc.info['name']}",
                })
    return detections

if __name__ == "__main__":
    print("🔍 Shadow AI Radar — scanning running processes...\n")
    found = scan_processes()
    if not found:
        print("No AI tools detected running right now.")
    else:
        for d in found:
            print(f"  [{d['risk'].upper():6}] {d['tool']:16} ({d['category']}) — {d['detail']}")
    print(f"\nDone. {len(found)} AI tool(s) detected.")