# Shadow AI Radar

A scanner that discovers the AI tools quietly running on a machine — running apps,
configured MCP servers, browser extensions, and exposed API keys — and (in progress)
streams the findings into a self-hosted [SigNoz](https://signoz.io) instance as a live
security dashboard with alerts.

Built for the **Agents of SigNoz** hackathon (WeMakeDevs, July 2026) · Track 03.

## The problem

Companies have little visibility into which AI tools their people actually use. Someone
installs a coding agent, wires up an MCP server with filesystem access, or leaves an API
key sitting in a plaintext `.env` — and no one can see it. This is "shadow AI," and the
first step to governing it is simply making it visible.

## What it detects

Shadow AI Radar sweeps a machine across four independent layers:

| Layer | Detects | Example finding |
|-------|---------|-----------------|
| 1. Running processes | AI desktop apps & agents currently running | Cursor, Claude Desktop, Ollama |
| 2. MCP configs | Configured MCP servers and their access level | filesystem server with broad access → HIGH |
| 3. Browser extensions | AI-related Chrome extensions & their permissions | Grammarly, AI assistants |
| 4. API-key exposure | AI/API keys in plaintext `.env` files | OpenAI / Anthropic key present → HIGH |

Each detection is tagged with a **risk tier** (low / medium / high) based on how much the
tool can access — a chat app is low; an agent that can read your whole home folder or a
key sitting in plaintext is high.

## Privacy by design

This is a security tool, so it holds itself to a strict contract:

- **It never transmits or stores secret values.** For API keys, it detects that a key
  *pattern* exists and records only the provider type and file path — never the key itself.
  (Detection without exfiltration.)
- **Scoped scanning** — it only looks where it's told to, and skips hidden/dependency
  folders (`.git`, `node_modules`, `venv`, …).
- **Local only** — findings go to a self-hosted SigNoz on the same machine. Nothing
  leaves the device.
- The `.gitignore` is strict enough that even test `.env` fixtures stay local.

## Running it

```bash
python3 -m venv venv
source venv/bin/activate
pip install psutil
python radar.py
```

### Trying the API-key layer (Layer 4)

Because `.env` files are gitignored (on purpose), the key-scanner's test fixture isn't in
this repo. To try it, create a fake one with obviously-fake values:

```bash
mkdir -p test_fixtures/fake_project
cat > test_fixtures/fake_project/.env << 'INNER'
OPENAI_API_KEY=sk-FAKEfake1234567890abcdefghij
ANTHROPIC_API_KEY=sk-ant-FAKEdonotusethisvalue
INNER
python radar.py
```

You'll see it flag the file as HIGH — while never printing the key values themselves.

## Reproducing the SigNoz deployment

This repo includes `casting.yaml` and `casting.yaml.lock`. With
[Foundry](https://signoz.io) installed:

```bash
foundryctl cast -f casting.yaml
```

SigNoz will come up at `localhost:8080`.

## Status

- ✅ Four-layer detection engine (processes, MCP, extensions, API keys)
- 🚧 Telemetry wiring into SigNoz (traces / logs / metrics)
- 🚧 Live dashboard + Slack alerts

## A note on AI assistance

Planning, research, and code review for this project were done with AI assistance;
all decisions, testing, and the final implementation are my own.
