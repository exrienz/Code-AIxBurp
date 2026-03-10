# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Code-AIxBurp Community Edition - A Burp Suite passive security scanner plugin that detects OWASP Top 10 vulnerabilities using AI providers.

**Single-file architecture:** `Code-AIxBurp.py` (~2,700 lines)

## Language & Runtime

- Python 2.7 (Jython for Burp Suite compatibility)
- Java Swing for UI components
- Burp Suite Extender API

## Installation

Drop `Code-AIxBurp.py` into Burp Suite's Extensions directory. No build step required.

## Configuration

- Persistent config: `~/.code_aixburp_config.json`
- Default AI: Ollama with `deepseek-r1:latest` model
- Supported providers:
  - **Ollama** - Local models (http://localhost:11434)
  - **OpenAI** - GPT models (https://api.openai.com/v1)
  - **Claude** - Anthropic models (https://api.anthropic.com/v1)
  - **Gemini** - Google models (https://generativelanguage.googleapis.com/v1)
  - **OpenAI Compatible** - Any OpenAI-compatible API (OpenRouter, Together AI, Groq, LM Studio, etc.)

**Using OpenAI-compatible providers:** Select "OpenAI Compatible" as provider, set the base URL (e.g., `https://openrouter.ai/api/v1` for OpenRouter), enter your API key, and specify the model name manually.

## Architecture

Main class `BurpExtender` implements Burp APIs (IBurpExtender, IHttpListener, IScannerCheck, ITab, IContextMenuFactory).

**Key subsystems:**
- **AI Integration** - 5 provider backends with connection testing (`_ask_ollama`, `_ask_openai`, `_ask_claude`, `_ask_gemini`, `_ask_openai_compatible`)
- **Analysis Pipeline** - Request capture → feature extraction → AI analysis → finding creation
- **UI Panels** - Statistics, Active Tasks, Findings, Console (all Swing-based)
- **Threading** - Rate-limited (4s delay) background analysis with daemon threads

**Critical methods:**
| Method | Purpose |
|--------|---------|
| `registerExtenderCallbacks()` | Plugin initialization |
| `_perform_analysis()` | Core scanning logic with deduplication |
| `ask_ai(prompt)` | Routes to appropriate AI provider |
| `build_prompt(data)` | Constructs OWASP-focused analysis prompt |
| `_repair_json()` | Multi-strategy JSON parsing with fallbacks |

## Implementation Details

- **Deduplication:** MD5 hash of URL to prevent duplicate analysis
- **Static file filtering:** Skips .js, .css, .jpg, .png, .gif, .ico, .woff, .woff2, .ttf, .svg
- **Thread safety:** Locks for UI/data access, EDT-aware Swing operations
- **Confidence mapping:** <50% skipped, 50-74% Tentative, 75-89% Firm, 90%+ Certain
- **JSON repair:** Attempts bracket fixes, regex extraction, and lenient parsing

## Community Edition Limitations

- Passive scanning only (no active verification)
- No WAF detection/evasion
- No out-of-band testing
- Limited payload libraries

## Debugging

Enable verbose logging via `VERBOSE = True` flag in the code. Console output visible in Burp's Output tab.
