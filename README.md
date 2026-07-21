# Shadow AI Radar

A scanner that discovers AI tools in use on a machine — running apps, configured MCP
servers, browser extensions, and exposed API keys — and streams the findings into a
self-hosted [SigNoz](https://signoz.io) instance as a live security dashboard with alerts.

Built for the **Agents of SigNoz** hackathon (WeMakeDevs, July 2026) · Track 03.

## The problem
Companies have little visibility into which AI tools their employees actually use. An
employee configures an MCP server with filesystem access, or leaves an API key in a
plaintext `.env` — and IT is blind to it. This is "shadow AI." Shadow AI Radar makes it
visible.

## How it works
1. A Python scanner sweeps the machine every 60s across four layers (processes, MCP
   configs, browser extensions, API-key exposure).
2. Each detection is tagged with a risk tier and emitted as OpenTelemetry data.
3. SigNoz ingests it as traces, logs, and metrics — shown on a dashboard, with a Slack
   alert on any high-risk finding.

## Security note
The scanner **never transmits secret values** — only metadata (e.g. "Anthropic key found
in ~/x/.env"), never the key itself.

## Setup
_Coming as the project is built during the hackathon._

## Status
🚧 In active development — hackathon build week.
