"""
Shadow AI Radar — Layer 1: running-process detection.
Privacy: reads only the process list (names). No file contents, no secrets.
"""
import psutil
import json
import os

# MCP config locations from DESIGN_NOTES.md §3 (macOS paths, verified)
MCP_CONFIG_PATHS = [
    "~/Library/Application Support/Claude/claude_desktop_config.json",  # Claude Desktop
    "~/.claude/claude_desktop_config.json",                            # Claude Code
    "~/.cursor/mcp.json",                                              # Cursor (global)
    "~/.continue/config.json",                                        # Continue
    "~/DeveloperHub/shadow-ai-radar/test_fixtures/fake_mcp_config.json",  # TEST ONLY - remove for real use
]

# Path arguments we treat as "broad access" -> HIGH risk
BROAD_PATHS = ["/", os.path.expanduser("~"), "/Users", "/home"]


def scan_mcp_configs():
    """Detect configured MCP servers and their access level.
    Privacy: reads config STRUCTURE only. Never stores env values / tokens."""
    detections = []

    for raw_path in MCP_CONFIG_PATHS:
        path = os.path.expanduser(raw_path)   # turn ~ into the real home path
        if not os.path.exists(path):
            continue                          # client not installed — skip safely

        try:
            with open(path, "r") as f:
                config = json.load(f)         # parse the JSON
        except (json.JSONDecodeError, OSError):
            continue                          # unreadable/broken file — skip, don't crash

        servers = config.get("mcpServers", {})
        for name, spec in servers.items():
            risk = "medium"                   # any configured server is at least medium
            reasons = []

            args = spec.get("args", [])
            # 1) filesystem-type server?
            if any("filesystem" in str(a) for a in args):
                # pull out the actual path arguments (the ones that look like paths)
                path_args = [str(a) for a in args if str(a).startswith("/") or str(a).startswith("~")]
                broad = False
                for p in path_args:
                    expanded = os.path.expanduser(p).rstrip("/")
                    # broad if it's root, /Users, /home, or a top-level home dir like /Users/<name>
                    parts = [seg for seg in expanded.split("/") if seg]
                    if expanded in ["", "/Users", "/home"] or len(parts) <= 2 and (expanded.startswith("/Users") or expanded.startswith("/home")):
                        broad = True
                if broad:
                    risk = "high"
                    reasons.append("filesystem access to a broad path")
                else:
                    reasons.append("filesystem access (scoped)")

            # 2) secret present in env?  (detect presence ONLY — never read the value)
            env = spec.get("env", {})
            if isinstance(env, dict):
                secret_like = [k for k in env.keys()
                               if any(t in k.upper() for t in ["TOKEN", "KEY", "SECRET"])]
                if secret_like:
                    risk = "high"
                    # we record only the VARIABLE NAMES, never their values
                    reasons.append(f"secret in env: {', '.join(secret_like)}")

            detections.append({
                "tool": f"MCP: {name}",
                "category": "mcp_server",
                "risk": risk,
                "detail": (f"in {os.path.basename(path)}"
                           + (f" — {'; '.join(reasons)}" if reasons else "")),
            })
    return detections
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
    print("🔍 Shadow AI Radar — full scan...\n")
    found = scan_processes() + scan_mcp_configs()   # Layer 1 + Layer 2
    if not found:
        print("No AI tools detected.")
    else:
        for d in found:
            print(f"  [{d['risk'].upper():6}] {d['tool']:22} ({d['category']}) — {d['detail']}")
    print(f"\nDone. {len(found)} detection(s).")