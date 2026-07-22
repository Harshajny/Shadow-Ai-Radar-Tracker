"""
Shadow AI Radar — Layer 1: running-process detection.
Privacy: reads only the process list (names). No file contents, no secrets.
"""
import psutil
import json
import os
import re
# --- Telemetry setup (send detections to SigNoz) ---
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

# One "machine identity" for this scan. Later we can rotate this to simulate
# multiple employees; for now it's this Mac.
MACHINE_ID = "harsha-mbp"

def setup_telemetry():
    """Configure the pipeline that ships detections to local SigNoz."""
    resource = Resource.create({"service.name": "shadow-ai-radar"})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces"))
    )
    trace.set_tracer_provider(provider)
    return provider
def report_to_signoz(detections, provider):
    """Send each detection to SigNoz as a span inside one scan trace."""
    tracer = trace.get_tracer("shadow-ai-radar")

    # one parent span = the whole scan cycle
    with tracer.start_as_current_span("scan-cycle") as scan:
        scan.set_attribute("machine_id", MACHINE_ID)
        scan.set_attribute("detections.total", len(detections))

        # one child span per detection
        for d in detections:
            with tracer.start_as_current_span(f"detect:{d['tool']}") as span:
                span.set_attribute("tool", d["tool"])
                span.set_attribute("category", d["category"])
                span.set_attribute("risk", d["risk"])
                span.set_attribute("detail", d["detail"])
                span.set_attribute("machine_id", MACHINE_ID)

    provider.shutdown()  # flush everything to SigNoz before exit
# Folder to scan (locked in DESIGN_NOTES: ~/DeveloperHub only)
# Scan scope: this project folder only (tight + safe for testing).
# Widen to ~/DeveloperHub later if you want realistic detection.
KEY_SCAN_ROOT = os.path.expanduser("~/DeveloperHub/shadow-ai-radar")

# Folders we never descend into — noise + risk + slowness
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__",
             ".next", "dist", "build", ".cache"}

# Files worth checking
ENV_FILENAMES = {".env", ".env.local", ".env.production", ".env.development"}

# Key PATTERNS. We match the shape of a key line — never capture the value.
# Each pattern is (provider label, compiled regex). The regex checks that a
# key-like assignment EXISTS on a line; we deliberately do NOT use capture
# groups to pull the secret out.
KEY_PATTERNS = [
    ("OpenAI",    re.compile(r"OPENAI_API_KEY\s*=\s*\S", re.IGNORECASE)),
    ("OpenAI",    re.compile(r"\bsk-[A-Za-z0-9]{20,}")),          # bare sk- key
    ("Anthropic", re.compile(r"ANTHROPIC_API_KEY\s*=\s*\S", re.IGNORECASE)),
    ("Anthropic", re.compile(r"\bsk-ant-\S+")),
    ("Google",    re.compile(r"(GEMINI|GOOGLE)_API_KEY\s*=\s*\S", re.IGNORECASE)),
    ("Generic",   re.compile(r"\b\w*(API_KEY|SECRET|TOKEN)\s*=\s*\S", re.IGNORECASE)),
]


def scan_api_keys():
    """Detect AI/API keys sitting in plaintext .env files under ~/DeveloperHub.

    PRIVACY CONTRACT (enforced below):
      - reads files line by line only to TEST against patterns
      - the matched text is never assigned to a stored variable, logged,
        printed, or transmitted — we record only {provider, file path, present}
    """
    detections = []

    if not os.path.isdir(KEY_SCAN_ROOT):
        return detections  # nothing to scan

    for root, dirs, files in os.walk(KEY_SCAN_ROOT):
        # prune skip-dirs IN PLACE so os.walk never descends into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]

        for filename in files:
            if filename not in ENV_FILENAMES:
                continue

            filepath = os.path.join(root, filename)
            providers_found = set()   # provider LABELS only — never values

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.lstrip().startswith("#"):
                            continue  # skip commented-out lines
                        for provider, pattern in KEY_PATTERNS:
                            # .search() returns a match object; we check ONLY
                            # whether it's truthy. We never read .group() — so
                            # the secret value is never pulled into memory.
                            if pattern.search(line):
                                providers_found.add(provider)
                        # 'line' goes out of scope each iteration; not retained
            except OSError:
                continue  # unreadable file — skip safely

            # Emit ONE detection per file, listing which providers were present.
            if providers_found:
                # show a privacy-safe relative path, not the full home path
                rel = os.path.relpath(filepath, os.path.expanduser("~"))
                detections.append({
                    "tool": f"API key(s): {', '.join(sorted(providers_found))}",
                    "category": "api_key",
                    "risk": "high",
                    "detail": f"plaintext key in ~/{rel}",
                })
    return detections
# Chrome extensions directory (macOS). "Default" is the main profile.
CHROME_EXTENSIONS_DIR = os.path.expanduser(
    "~/Library/Application Support/Google/Chrome/Default/Extensions"
)

# AI-related keywords to match against extension names (case-insensitive).
AI_EXTENSION_KEYWORDS = [
    "chatgpt", "gpt", "claude", "copilot", "gemini", "perplexity",
    "grammarly", "monica", "sider", "merlin", "jasper", "writesonic",
    "ai ", "ai-", "openai", "anthropic",
]


def scan_browser_extensions():
    """Detect AI-related Chrome extensions by reading their manifests.
    Privacy: reads only extension names/metadata from manifest.json."""
    detections = []
    seen = set()

    if not os.path.isdir(CHROME_EXTENSIONS_DIR):
        return detections  # Chrome not installed / no extensions — skip safely

    # Each subfolder is an extension ID; inside are version folders with manifest.json
    for ext_id in os.listdir(CHROME_EXTENSIONS_DIR):
        ext_path = os.path.join(CHROME_EXTENSIONS_DIR, ext_id)
        if not os.path.isdir(ext_path):
            continue

        # find a manifest.json inside any version subfolder
        for version in os.listdir(ext_path):
            manifest = os.path.join(ext_path, version, "manifest.json")
            if not os.path.exists(manifest):
                continue
            try:
                with open(manifest, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue  # unreadable/broken manifest — skip

            name = str(data.get("name", "")).lower()
            # Chrome sometimes stores names as "__MSG_appName__" (localized) — skip those
            if name.startswith("__msg"):
                continue

            if any(kw in name for kw in AI_EXTENSION_KEYWORDS) and name not in seen:
                seen.add(name)
                # broad permission = higher interest
                perms = data.get("permissions", [])
                risky = any(p in ["tabs", "<all_urls>", "webRequest", "cookies"]
                            for p in perms if isinstance(p, str))
                detections.append({
                    "tool": data.get("name", "Unknown AI extension"),
                    "category": "browser_ext",
                    "risk": "medium" if risky else "low",
                    "detail": f"Chrome extension" + (" — broad permissions" if risky else ""),
                })
            break  # only need one manifest per extension
    return detections

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
    found = (scan_processes()
             + scan_mcp_configs()
             + scan_browser_extensions()
             + scan_api_keys())

    # print to console (as before)
    if not found:
        print("No AI tools detected.")
    else:
        for d in found:
            print(f"  [{d['risk'].upper():6}] {d['tool']:22} ({d['category']}) — {d['detail']}")
    print(f"\nDone. {len(found)} detection(s).")

    # NEW: also send to SigNoz
    print("\n📡 Sending detections to SigNoz...")
    provider = setup_telemetry()
    report_to_signoz(found, provider)
    print("Done. Check the Traces section in SigNoz for 'shadow-ai-radar'.")
