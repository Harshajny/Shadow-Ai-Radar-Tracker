# 🛰 Shadow AI Radar

**Discover the AI tools quietly running on a machine — apps, coding agents, MCP servers, and exposed API keys — and stream them into [SigNoz](https://signoz.io) as a live security dashboard with real-time Slack alerts.**

Built for the **Agents of SigNoz** hackathon (WeMakeDevs, July 2026) · **Track 03: Build Your Own**.

<!-- Suggested: drop your best screenshot here (the colorized console scan output) -->

<!-- ![Shadow AI Radar console output](docs/console.png) -->

---

## The problem

Shadow AI — employees using AI tools without approval or oversight — is one of 2026's fastest-growing security risks:

- **98%** of organizations have employees using unsanctioned AI tools.
- **49%** of workers use AI in ways their employer hasn't approved; **58%** of them on free tools with no data governance.
- **86%** of IT leaders reported a negative incident tied to unapproved AI in the past year.
- Yet only **~25%** of organizations have comprehensive visibility into how employees use AI.

The problem isn't that AI is used — it's that it's used **invisibly**. You can't secure what you can't see. Shadow AI Radar makes the invisible visible, focusing on the newest and least-watched corner: AI agents, MCP servers, and secrets living **on the machine itself**.

---

## What it detects

Shadow AI Radar sweeps a machine across **four independent detection layers**:

| Layer                             | Detects                                          | Example finding                     | Risk           |
| --------------------------------- | ------------------------------------------------ | ----------------------------------- | -------------- |
| **1 · Processes**          | AI desktop apps & agents currently running       | Cursor, Claude Desktop, Ollama      | low–medium    |
| **2 · MCP configs**        | Configured MCP servers*and their access level* | Filesystem server with broad access | **HIGH** |
| **3 · Browser extensions** | AI-related Chrome extensions & permissions       | Grammarly, AI assistants            | low–medium    |
| **4 · API-key exposure**   | AI provider keys in plaintext`.env` files      | OpenAI / Anthropic key present      | **HIGH** |

Every detection is tagged with a **risk tier** based on **blast radius** — how much the tool can actually access. A chat app that just talks is `low`. A code editor is `medium`. An agent or MCP server that can read your whole home folder, or a secret sitting in a config, is `high`.

---

## How it uses SigNoz — all five signals

This project leans on SigNoz deeply, using **every core observability signal**:

- **Traces** — each scan cycle is a trace; each detection is a nested span with attributes (`tool`, `category`, `risk`, `machine_id`).
- **Logs** — each detection emits a human-readable log line; the dashboard panels are built from these.
- **Metrics** — a counter (`ai_tools_detected_total`) tracks detections over time by risk and category.
- **Dashboards** — a live 5-panel security dashboard: high/medium/low risk counts, total scans, and a per-machine fleet-activity list.
- **Alerts** — a rule fires a **real-time Slack alert** the moment any high-risk detection appears.

**Why SigNoz specifically:**

- **OpenTelemetry-native** — detections are emitted with the standard OTel SDK; no proprietary agent, no lock-in.
- **One platform for traces + logs + metrics** — correlated in one place, which made this shippable solo in a week.
- **Self-hosted = data never leaves the machine** — essential for a *security* tool that reads configs and scans for keys. A SaaS backend would undercut the entire privacy premise.
- **Dashboards & alerting built in** — so development time went to detection logic, not observability plumbing.
- **Reproducible** — the whole stack deploys from a declared `casting.yaml`, so anyone can stand up an identical instance.

---

## Privacy by design — "detection without exfiltration"

This is a security tool, so it holds itself to a strict privacy contract, enforced in the code's structure:

- **It never stores or transmits secret values.** For API keys, it tests each line against a *pattern* and records only the provider type and file path — never the key itself. In code, it only ever calls `pattern.search(line)` and checks whether the result is truthy; it never calls `.group()` to extract the matched text. The secret is tested against, never captured.
- **Scoped scanning** — only scans a configured directory; skips hidden/dependency folders (`.git`, `node_modules`, `venv`, …).
- **Local only** — telemetry goes to a SigNoz instance on the same machine. Nothing leaves the device.
- **MCP/config reads = metadata only** — server names and access levels, never the token values inside `env` blocks.
- The `.gitignore` is strict enough that even test `.env` fixtures stay local.

---

## Architecture

```
┌─────────────────────────────┐
│  Machine (your Mac)         │
│                             │
│  radar.py                   │   every run:
│  ├─ Layer 1: processes      │   scan → tag risk → emit
│  ├─ Layer 2: MCP configs    │
│  ├─ Layer 3: browser exts   │
│  ├─ Layer 4: API keys       │
│  └─ OpenTelemetry SDK  ──────┼──── OTLP (localhost:4318)
└─────────────────────────────┘             │
                                            ▼
┌──────────────────────────────────────────────────┐
│  SigNoz (self-hosted, local)                     │
│  Collector → ClickHouse → Dashboard + Alert Rule │
└───────────────────────────────┬──────────────────┘
                                 │ high-risk detected
                                 ▼
                          🚨 Slack #shadow-ai-alerts
```

---

## Quickstart

**Prerequisites:** Docker, Python 3.9+, and a self-hosted SigNoz instance (see below).

**1. Stand up SigNoz** (via [Foundry](https://signoz.io)):

```bash
foundryctl cast -f casting.yaml
# SigNoz UI at http://localhost:8080
```

**2. Set up the scanner:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install psutil opentelemetry-sdk opentelemetry-exporter-otlp-proto-http
```

**3. Run a scan:**

```bash
python radar.py
```

You'll see a colorized report of every AI tool detected on the machine, with risk tiers — and the detections stream into SigNoz. Run it a few times to populate the dashboard across the simulated fleet.

### Trying the API-key layer

Because `.env` files are gitignored (on purpose), the key-scanner's test fixture isn't in this repo. To try it, create a fake one with obviously-fake values:

```bash
mkdir -p test_fixtures/fake_project
cat > test_fixtures/fake_project/.env << 'EOF'
OPENAI_API_KEY=sk-FAKEfake1234567890abcdefghij
ANTHROPIC_API_KEY=sk-ant-FAKEdonotusethisvalue
EOF
python radar.py
```

It will flag the file as HIGH — while never printing the key values themselves.

---

## Screenshots

<!-- Drop your three best screenshots here: -->

<!-- ![Console scan output](docs/console.png) -->

<!-- ![SigNoz security dashboard](docs/dashboard.png) -->

<!-- ![Live Slack alert firing](docs/slack-alert.png) -->

![1784835306902](image/README/ConsoleScanOutput.png)


![1784835607449](image/README/LiveSlackAlertFiring.png)


![1784835689339](image/README/SigNozSecurityDashboard.png)

---

## Note on the demo fleet

To demonstrate fleet-wide monitoring from a single machine, the scanner tags detections with a rotating `machine_id` (simulating several "employee" machines). This is **simulated for the demo** — in real use, each machine reports under its own identity.

---

## Reproducing the SigNoz deployment

This repo includes `casting.yaml` and `casting.yaml.lock`. With Foundry installed:

```bash
foundryctl cast -f casting.yaml
```

SigNoz will come up at `localhost:8080` with an identical configuration.

---

## Built with

- **Python** (`psutil`, `re`, standard library) — the scanner
- **OpenTelemetry SDK** — traces, logs, metrics
- **SigNoz** (self-hosted via Foundry / Docker) — observability backend, dashboard, alerting
- **Slack incoming webhooks** — real-time alerting

---

## A note on AI assistance

AI assistance was used for planning, research, and code review throughout this project. All design decisions, testing, debugging, and the final implementation are my own.

---

*Shadow AI Radar · Agents of SigNoz hackathon 2026 · Track 03*
