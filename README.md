# Code-AIxBurp

AI-powered Burp Suite extension for OWASP-focused vulnerability detection, AI-assisted verification, and optional OOB/Intruder workflows.

- Version: `1.2.0`
- Runtime: `Jython (Python 2.7)`
- Architecture: single file (`Code-AIxBurp.py`)

## Table of Contents

- [What It Does](#what-it-does)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [AI Providers](#ai-providers)
- [How Scanning Works](#how-scanning-works)
- [Verification, OOB, and Intruder](#verification-oob-and-intruder)
- [UI Overview](#ui-overview)
- [Troubleshooting](#troubleshooting)
- [Limitations and Notes](#limitations-and-notes)
- [Developer Notes](#developer-notes)
- [Changelog](#changelog)
- [License](#license)

## What It Does

`Code-AIxBurp` passively inspects in-scope HTTP traffic, sends request/response context to an AI provider, parses structured JSON findings, and creates Burp scan issues with:

- severity
- confidence
- CWE mapping
- OWASP mapping
- remediation text

It also includes optional verification helpers:

- AI-generated safe payload verification
- WAF fingerprinting/evasion payload variants
- Burp Collaborator OOB probes
- Intruder payload automation

## Key Features

- Multi-provider AI support:
  - Ollama
  - OpenAI
  - Claude (Anthropic)
  - Gemini
  - OpenAI-compatible APIs (OpenRouter, Together, Groq, LM Studio, etc.)
- Passive scanning pipeline with:
  - scope checks
  - static-file skipping
  - deduplication
  - rate limiting
- Burp issue creation from AI JSON output
- Findings panel with verification state tracking (`Pending`, `Verifying...`, `Confirmed`, `False Positive`, `Uncertain`, `Error`)
- Verification engine:
  - AI payload generation
  - response analysis
  - heuristic fallback logic
  - configurable retry attempts
- WAF-aware behavior:
  - signature-based WAF detection
  - optional payload transformation/evasion variants
- OOB support via Burp Collaborator when available
- Intruder integration:
  - context-menu send to Intruder
  - custom payload generator factory
- Persistent settings in `~/.code_aixburp_config.json`
- Built-in diagnostics for stuck or queued tasks

## Requirements

- Burp Suite with Extender support
- Jython `2.7.x` configured in Burp (Python extensions run via Jython)
- Network access to your selected AI provider

Optional/feature-specific:

- Burp Collaborator support for OOB features
- Burp Intruder for automated fuzzing workflows

## Installation

1. Download or copy `Code-AIxBurp.py`.
2. In Burp Suite, set Jython:
   - `Extender -> Options -> Python Environment`
   - Select your `jython-standalone-2.7.x.jar`
3. Load the extension:
   - `Extender -> Extensions -> Add`
   - Extension type: `Python`
   - Select `Code-AIxBurp.py`
4. Open the `Code-AIxBurp` tab in Burp.
5. Click `Settings` and configure provider/model/keys.

## Quick Start

1. Add your target to Burp scope.
2. Ensure `Passive Scanning` is enabled in Settings.
3. Browse the target through Burp Proxy.
4. Watch `Active Tasks`, `Findings`, and `Console` in the extension tab.
5. Use `Verify Selected` on findings you want to validate.

Manual actions are available via right-click context menu in request/history views.

## Configuration

Settings are saved to:

```text
~/.code_aixburp_config.json
```

### Main Settings

| Setting | Default | Notes |
|---|---|---|
| `ai_provider` | `Ollama` | Provider selector in Settings |
| `api_url` | `http://localhost:11434` | Base URL for provider |
| `api_key` | empty | Required for most cloud providers |
| `model` | `deepseek-r1:latest` | AI model name |
| `max_tokens` | `2048` | Request output token cap |
| `ai_request_timeout` | `60` | Seconds; range `10-99999` |
| `passive_scanning_enabled` | `true` | Auto-scan proxy/scanner passive traffic |
| `enable_waf_detection` | `true` | WAF fingerprinting |
| `enable_waf_evasion` | `true` | Evasion payload transforms |
| `enable_advanced_payloads` | `true` | Payload libraries per vuln family |
| `enable_oob_testing` | `true` | Burp Collaborator probes |
| `enable_intruder_automation` | `true` | Intruder payload generator + menu action |
| `max_verification_attempts` | `4` | Verification candidate attempts (`1-10`) |
| `oob_poll_seconds` | `18` | Poll window for collaborator interactions (`6-120`) |
| `theme` | `Light` | Console theme (`Light`/`Dark`) |
| `verbose` | `true` | Extra output in Burp Output/Console |

### Example Config

```json
{
  "ai_provider": "OpenAI Compatible",
  "api_url": "https://openrouter.ai/api/v1",
  "api_key": "sk-...",
  "model": "anthropic/claude-3.7-sonnet",
  "max_tokens": 2048,
  "ai_request_timeout": 90,
  "passive_scanning_enabled": true,
  "enable_waf_detection": true,
  "enable_waf_evasion": true,
  "enable_advanced_payloads": true,
  "enable_oob_testing": true,
  "enable_intruder_automation": true,
  "max_verification_attempts": 4,
  "oob_poll_seconds": 18,
  "theme": "Light",
  "verbose": true
}
```

## AI Providers

### Built-in provider URLs

- Ollama: `http://localhost:11434`
- OpenAI: `https://api.openai.com/v1`
- Claude: `https://api.anthropic.com/v1`
- Gemini: `https://generativelanguage.googleapis.com/v1`
- OpenAI Compatible: any API implementing OpenAI-style `/chat/completions`

### OpenAI-Compatible setup

1. Set provider to `OpenAI Compatible`.
2. Set base URL (for example `https://openrouter.ai/api/v1`).
3. Enter API key.
4. Enter model name manually if model listing is unsupported.

## How Scanning Works

1. A response is observed in Proxy/passive scanner path.
2. URL is validated:
   - must be in Burp scope
   - must not match static extensions
3. Request is queued with rate limit (`min_delay = 4s`).
4. Request/response features are extracted (headers/body/params/status).
5. AI is prompted to return JSON-only findings.
6. JSON is parsed with repair fallbacks for malformed responses.
7. Findings are deduplicated and confidence-filtered.
8. Burp issues are created and shown in Findings table.

### Confidence Mapping

- `< 50`: dropped
- `50-74`: `Tentative`
- `75-89`: `Firm`
- `90+`: `Certain`

### Static Extensions Skipped

`js`, `gif`, `jpg`, `png`, `ico`, `css`, `woff`, `woff2`, `ttf`, `svg`

## Verification, OOB, and Intruder

### Verification Flow

For a selected finding:

1. Build a vulnerability-family-aware verification prompt.
2. Ask AI for a safe JSON payload plan.
3. Inject payload into parameter/header.
4. Replay request and analyze response.
5. Optionally run OOB collaborator probe for relevant families.
6. Update finding status and evidence.

### Vulnerability Families

- `sqli`
- `xss`
- `command_injection`
- `path_traversal`
- `ssrf`
- `ssti`
- `generic`

### WAF Support

- Detection via headers/body signatures and block-page heuristics
- Stores per-host WAF profile
- Optional payload transforms (encoding/case/comment obfuscation/context variants)

### OOB Support

Uses Burp Collaborator client context to:

- generate collaborator payloads
- inject and replay requests
- poll interactions for a configurable duration

If Collaborator is unavailable, extension logs and continues without OOB confirmation.

### Intruder Support

- Context action: `Automated Fuzzing: Send to Intruder (Advanced Payloads)`
- Payload generator name: `Code-AIxBurp - Advanced Payload Library`
- Auto-derives insertion points from request parameters when possible

## UI Overview

Main `Code-AIxBurp` tab includes:

- `Statistics` panel
- `Active Tasks` table
- `Findings` table
- `Console` panel

Controls:

- `Settings`
- `Clear Completed`
- `Cancel All Tasks`
- `Pause All Tasks` (toggle pause/resume)
- `Project Updates`

Findings right-click actions:

- Verify finding
- Verify all pending
- Run OOB probe for selected finding
- Send finding request to Intruder
- Mark as false positive/confirmed

## Troubleshooting

### AI connection test fails

- Verify base URL, API key, and model.
- Increase timeout in Settings.
- For Ollama, confirm local daemon is running and model exists.

### No findings appear

- Ensure target is in Burp scope.
- Confirm passive scanning is enabled.
- Check static resource filtering (file extension may be skipped).
- Check confidence threshold behavior (`<50` is discarded).

### Malformed AI output / JSON parse errors

- Extension attempts automatic JSON repair.
- If still failing, switch to a model that follows strict JSON better.
- Reduce model temperature (verification uses low temperature already).

### Tasks appear stuck

- Use `Run Task Diagnostics` in Settings.
- Use `Cancel All Tasks` to clear queue.
- Increase request timeout for slower models.

### OOB results never confirm

- Confirm Burp Collaborator is available in your Burp edition/environment.
- Increase `OOB Poll Time`.
- Verify target egress/network policies allow outbound callbacks.

### Intruder payload generator missing

- Ensure `Intruder Automation` is enabled.
- Re-open Settings and save to force factory re-sync.

## Limitations and Notes

- `doActiveScan()` returns empty; this extension does not use Burp active scanner insertion-point logic.
- AI output quality directly affects detection quality.
- Verification is designed for safe, non-destructive checks but still sends modified requests.
- Use only on systems you are authorized to test.

## Developer Notes

- Core file: `Code-AIxBurp.py`
- Important methods:
  - `registerExtenderCallbacks()`
  - `_perform_analysis()`
  - `build_prompt()`
  - `ask_ai()` and provider adapters
  - `verify_finding()`
  - `_detect_waf_profile()`
  - `_run_oob_probe_for_message()`
- Threading:
  - background worker threads for scan/verification/actions
  - semaphore + delay for request pacing
  - Swing UI updates via `invokeLater`
- Logging:
  - set `VERBOSE` in settings for detailed output

## Changelog

- `v1.2.0` (2026-03-10): WAF detection/evasion, advanced payload libraries, OOB collaborator testing, Intruder automation
- `v1.1.1` (2025-02-04): moved network calls off EDT to prevent UI freeze
- `v1.1.0` (2025-02-04): Linux UI responsiveness improvements
- `v1.0.9` (2025-01-31): static-file skipping, passive scan toggle
- `v1.0.0` (2025-01-31): initial stable release

## License

MIT License
