# 🔍 log-analyzer-ai

**AI-powered log analysis using local LLMs** — Transform your logs into actionable insights with natural language queries.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-green.svg)](https://ollama.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<p align="center">
  <img src="docs/demo.png" alt="Log Analyzer Demo" width="700">
</p>

## ✨ Features

- 🤖 **AI-Powered Analysis** — Uses local LLMs (Ollama) to understand and explain your logs
- 💬 **Natural Language Queries** — Ask questions like "What errors happened in the last hour?"
- 📊 **Pattern Detection** — Automatically identifies anomalies and recurring issues
- 🎨 **Severity Classification** — Color-coded output (CRITICAL, ERROR, WARNING, INFO, DEBUG)
- 📋 **Multiple Output Formats** — Terminal, JSON, or beautiful HTML reports
- 🔌 **Format Auto-Detection** — Works with syslog, nginx, Apache, JSON logs, and more
- 🔒 **100% Local** — Your logs never leave your machine

## 🚀 Quick Start

### Prerequisites

1. **Python 3.8+**
2. **Ollama** with a model installed:
   ```bash
   # Install Ollama from https://ollama.ai
   ollama pull qwen2.5:3b  # Recommended: fast and capable
   ```

### Installation

```bash
# Clone the repository
git clone https://github.com/tommieseals/log-analyzer-ai.git
cd log-analyzer-ai

# Install dependencies
pip install -r requirements.txt

# Make it executable (optional)
chmod +x log_analyzer.py
```

### Basic Usage

```bash
# Analyze a log file
./log_analyzer.py /var/log/syslog

# Ask a specific question
./log_analyzer.py app.log --query "What caused the service to crash?"

# Analyze last 100 lines with HTML output
./log_analyzer.py nginx.log --tail 100 --format html --output report.html

# Pipe from other commands
journalctl -u myservice | ./log_analyzer.py - --query "Find authentication failures"
```

## 📖 Usage Examples

### Natural Language Queries

```bash
# Find security issues
./log_analyzer.py /var/log/auth.log --query "Were there any failed login attempts?"

# Debug application errors
./log_analyzer.py app.log --query "Why did the database connection fail?"

# Performance analysis
./log_analyzer.py nginx_access.log --query "Which endpoints are slowest?"
```

### Time-Based Filtering

```bash
# Last hour only
./log_analyzer.py /var/log/syslog --since 1h

# Last 30 minutes
./log_analyzer.py app.log --since 30m --query "What went wrong?"

# Last 2 days
./log_analyzer.py /var/log/messages --since 2d
```

### Output Formats

```bash
# Terminal output (default) - colored and formatted
./log_analyzer.py app.log

# JSON output - perfect for pipelines
./log_analyzer.py app.log --format json | jq '.ai_analysis'

# HTML report - shareable and professional
./log_analyzer.py app.log --format html --output analysis.html
```

### Stats Only (No AI)

```bash
# Quick stats without LLM analysis
./log_analyzer.py large_file.log --no-ai
```

## 📊 Example Output

### Terminal Output

```
═══════════════════════════════════════════════════════════
📊 LOG ANALYSIS REPORT
═══════════════════════════════════════════════════════════

📁 Source: /var/log/syslog
📏 Lines analyzed: 1,247
📋 Log format: syslog

📈 Severity Distribution:
  CRITICAL   ██ 2
  ERROR      ████████ 23
  WARNING    ███████████████ 45
  INFO       ██████████████████████████████████████████ 1,177

🤖 AI Analysis (qwen2.5:3b):
───────────────────────────────────────────────────────────
**Summary:**
The logs show a generally healthy system with some notable issues:

• **2 Critical Events:** OOM killer activated twice, terminating processes
• **23 Errors:** Primarily failed SSH authentication attempts (possible brute force)
• **Pattern Detected:** Repeated connection attempts from IP 192.168.1.105

**Recommendations:**
1. Investigate memory pressure causing OOM events
2. Consider fail2ban for SSH protection
3. Review the source IP 192.168.1.105 for potential threats
```

### JSON Output

```json
{
  "statistics": {
    "total_lines": 1247,
    "severity_counts": {
      "INFO": 1177,
      "WARNING": 45,
      "ERROR": 23,
      "CRITICAL": 2
    },
    "log_format": "syslog"
  },
  "ai_analysis": "The logs show a generally healthy system...",
  "query": null,
  "model": "qwen2.5:3b",
  "timestamp": "2024-01-15T10:30:00"
}
```

## 🛠️ Command Reference

```
usage: log_analyzer.py [-h] [-q QUERY] [-t TAIL] [-s SINCE] 
                       [-f {text,json,html}] [-o OUTPUT] 
                       [--model MODEL] [--host HOST] 
                       [--no-ai] [-v] logfile

Arguments:
  logfile              Log file path or "-" for stdin

Options:
  -q, --query QUERY    Natural language query about the logs
  -t, --tail TAIL      Only analyze last N lines
  -s, --since SINCE    Analyze logs since (e.g., 1h, 30m, 2d)
  -f, --format FORMAT  Output format: text, json, html (default: text)
  -o, --output FILE    Output file (default: stdout)
  --model MODEL        Ollama model to use (default: qwen2.5:3b)
  --host HOST          Ollama API host (default: http://localhost:11434)
  --no-ai              Skip AI analysis, show stats only
  -v, --verbose        Verbose output
```

## 🔧 Supported Log Formats

The tool auto-detects these formats:

| Format | Example |
|--------|---------|
| **Syslog** | `Jan 15 10:30:00 hostname service[123]: message` |
| **Nginx Access** | `127.0.0.1 - - [15/Jan/2024:10:30:00] "GET /api" 200` |
| **Nginx Error** | `2024/01/15 10:30:00 [error] 123#0: message` |
| **Apache** | `127.0.0.1 - - [15/Jan/2024:10:30:00] "GET /" 200` |
| **JSON Lines** | `{"timestamp": "...", "level": "ERROR", "message": "..."}` |
| **Generic** | `2024-01-15T10:30:00 [ERROR] message` |

## 🧠 Model Recommendations

| Model | Size | Speed | Best For |
|-------|------|-------|----------|
| `qwen2.5:3b` | 2GB | ⚡⚡⚡ | Quick analysis, most use cases |
| `llama3.2:3b` | 2GB | ⚡⚡⚡ | Good alternative |
| `mistral:7b` | 4GB | ⚡⚡ | More detailed analysis |
| `codellama:7b` | 4GB | ⚡⚡ | Code/stack trace heavy logs |

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Log Files  │────▶│ Log Analyzer │────▶│   Output    │
│  or stdin   │     │   (Python)   │     │ text/json/  │
└─────────────┘     └──────┬───────┘     │    html     │
                          │              └─────────────┘
                          ▼
                   ┌──────────────┐
                   │   Ollama     │
                   │ (Local LLM)  │
                   └──────────────┘
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Ollama](https://ollama.ai) for making local LLMs accessible
- The open-source AI community for amazing models

---

<p align="center">
  <b>Made with 🤖 + ☕ by <a href="https://github.com/tommieseals">Tommie Seals</a></b>
</p>
