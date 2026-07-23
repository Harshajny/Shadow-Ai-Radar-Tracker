"""
Shadow AI Radar — Layer 1: running-process detection.
Privacy: reads only the process list (names). No file contents, no secrets.
"""
import psutil
import json
import os
import re
import random
# --- Telemetry setup (send detections to SigNoz) ---
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry import metrics
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
import logging
# --- Console styling (no external libraries needed) ---
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"

RISK_STYLE = {
    "high":   (C.RED,    "●"),
    "medium": (C.YELLOW, "●"),
    "low":    (C.GREEN,  "●"),
}

CATEGORY_LABEL = {
    "chat_app":    "Chat app",
    "code_agent":  "Code agent",
    "local_llm":   "Local LLM",
    "mcp_server":  "MCP server",
    "browser_ext": "Browser ext",
    "api_key":     "API key",
}

def print_report(detections, machine_id):
    """Pretty, colorized console report of all detections."""
    print()
    print(f"{C.CYAN}{C.BOLD}  ╭─────────────────────────────────────────────────────╮{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  │            🛰   SHADOW AI RADAR   ·   scan            │{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  ╰─────────────────────────────────────────────────────╯{C.RESET}")
    print(f"  {C.DIM}machine:{C.RESET} {C.BOLD}{machine_id}{C.RESET}")
    print()

    if not detections:
        print(f"  {C.GREEN}✓ No AI tools detected.{C.RESET}\n")
        return

    # sort so HIGH shows first
    order = {"high": 0, "medium": 1, "low": 2}
    for d in sorted(detections, key=lambda x: order.get(x["risk"], 3)):
        color, dot = RISK_STYLE.get(d["risk"], (C.GRAY, "○"))
        tier = d["risk"].upper()
        cat = CATEGORY_LABEL.get(d["category"], d["category"])
        tool = d["tool"] if len(d["tool"]) <= 34 else d["tool"][:31] + "..."
        print(f"  {color}{dot} {tier:<6}{C.RESET} {C.BOLD}{tool:<36}{C.RESET}"
              f"{C.DIM}{cat:<12}{C.RESET} {C.GRAY}{d['detail']}{C.RESET}")

    # summary line
    highs = sum(1 for d in detections if d["risk"] == "high")
    meds  = sum(1 for d in detections if d["risk"] == "medium")
    lows  = sum(1 for d in detections if d["risk"] == "low")
    print()
    print(f"  {C.DIM}─────────────────────────────────────────────────────{C.RESET}")
    summary = (f"  {C.BOLD}{len(detections)} detections{C.RESET}   "
               f"{C.RED}● {highs} high{C.RESET}   "
               f"{C.YELLOW}● {meds} medium{C.RESET}   "
               f"{C.GREEN}● {lows} low{C.RESET}")
    print(summary)
    if highs:
        print(f"  {C.RED}{C.BOLD}⚠  {highs} high-risk finding(s) — check the SigNoz dashboard.{C.RESET}")
    print()
# One "machine identity" for this scan. Later we can rotate this to simulate
# multiple employees; for now it's this Mac.
# Simulated employee machines (A5 decision: simulate a fleet from one Mac).
# Each run picks one, so repeated runs populate the dashboard as a real fleet.
EMPLOYEE_MACHINES = [
    "harsha-mbp",
    "priya-laptop",
    "dev-machine-03",
    "intern-macbook",
]
_counter_file = os.path.join(os.path.dirname(__file__), ".run_counter")
try:
    with open(_counter_file) as f:
        _n = int(f.read().strip())
except (OSError, ValueError):
    _n = 0
MACHINE_ID = EMPLOYEE_MACHINES[_n % len(EMPLOYEE_MACHINES)]
with open(_counter_file, "w") as f:
    f.write(str(_n + 1))

def setup_telemetry():
    """Configure traces, logs, and metrics — all shipping to local SigNoz."""
    resource = Resource.create({"service.name": "shadow-ai-radar"})

    # --- Traces (as before) ---
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4318/v1/traces"))
    )
    trace.set_tracer_provider(tracer_provider)

    # --- Logs ---
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(OTLPLogExporter(endpoint="http://localhost:4318/v1/logs"))
    )
    set_logger_provider(logger_provider)
    # bridge Python's logging module to OTel so log lines get shipped
    handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    otel_logger = logging.getLogger("shadow-ai-radar")
    otel_logger.setLevel(logging.INFO)
    otel_logger.addHandler(handler)

    # --- Metrics ---
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint="http://localhost:4318/v1/metrics")
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    return tracer_provider, logger_provider, meter_provider, otel_logger

def report_to_signoz(detections, providers):
    """Send detections to SigNoz as spans + logs + metrics."""
    tracer_provider, logger_provider, meter_provider, log = providers
    tracer = trace.get_tracer("shadow-ai-radar")
    meter = metrics.get_meter("shadow-ai-radar")

    # metric: a counter of detections, tagged by risk + category
    detection_counter = meter.create_counter(
        "ai_tools_detected_total",
        description="Count of AI tool detections",
    )

    high_risk = 0
    with tracer.start_as_current_span("scan-cycle") as scan:
        scan.set_attribute("machine_id", MACHINE_ID)
        scan.set_attribute("detections.total", len(detections))

        for d in detections:
            # span (as before)
            with tracer.start_as_current_span(f"detect:{d['tool']}") as span:
                span.set_attribute("tool", d["tool"])
                span.set_attribute("category", d["category"])
                span.set_attribute("risk", d["risk"])
                span.set_attribute("detail", d["detail"])
                span.set_attribute("machine_id", MACHINE_ID)

            # metric: increment counter with labels
            detection_counter.add(1, {
                "risk": d["risk"],
                "category": d["category"],
                "machine_id": MACHINE_ID,
            })

            # log: one human-readable line per detection
            log.info(
                f"[{d['risk'].upper()}] {d['tool']} ({d['category']}) — {d['detail']}",
                extra={"risk": d["risk"], "category": d["category"], "machine_id": MACHINE_ID},
            )

            if d["risk"] == "high":
                high_risk += 1

    # a summary log line — useful for the alert story
    log.info(f"Scan complete on {MACHINE_ID}: {len(detections)} detections, {high_risk} high-risk")

    # flush all three pipelines before exit
    tracer_provider.shutdown()
    logger_provider.shutdown()
    meter_provider.shutdown() # flush everything to SigNoz before exit
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
    found = (scan_processes()
             + scan_mcp_configs()
             + scan_browser_extensions()
             + scan_api_keys())

    print_report(found, MACHINE_ID)

    # send to SigNoz (traces + logs + metrics) — unchanged
    print(f"  📡 Streaming to SigNoz...")
    providers = setup_telemetry()
    report_to_signoz(found, providers)
    print(f"  ✓ Sent. View the Shadow AI Radar dashboard at localhost:8080\n")