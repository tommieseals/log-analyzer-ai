#!/usr/bin/env python3
"""
log-analyzer-ai: LLM-powered log analysis tool using Ollama.

Analyze logs with natural language queries, detect patterns,
classify severity, and generate insights using local AI models.
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Iterator, List, Dict, Any
import subprocess

try:
    import requests
except ImportError:
    print("Installing requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Severity levels and their colors
SEVERITY_COLORS = {
    'CRITICAL': Colors.RED + Colors.BOLD,
    'ERROR': Colors.RED,
    'WARNING': Colors.YELLOW,
    'INFO': Colors.GREEN,
    'DEBUG': Colors.DIM,
}

# Common log patterns for auto-detection
LOG_PATTERNS = {
    'syslog': r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$',
    'nginx_access': r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"',
    'nginx_error': r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+#\d+):\s*(.*)$',
    'apache': r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+|-)',
    'json': r'^\s*\{.*\}\s*$',
    'generic': r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*[\[\(]?(\w+)[\]\)]?\s*(.*)$',
}

class OllamaClient:
    """Client for Ollama API."""
    
    def __init__(self, host: str = "http://localhost:11434", model: str = "qwen2.5:3b"):
        self.host = host.rstrip('/')
        self.model = model
        self.timeout = 120
        
    def is_available(self) -> bool:
        """Check if Ollama is running."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def generate(self, prompt: str, system: str = None) -> str:
        """Generate a response from the model."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
            
        try:
            resp = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except requests.exceptions.Timeout:
            return "Error: Request timed out. Try a shorter log segment."
        except Exception as e:
            return f"Error: {str(e)}"


class LogAnalyzer:
    """Main log analysis engine."""
    
    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama
        self.stats = Counter()
        
    def detect_format(self, sample_lines: List[str]) -> str:
        """Auto-detect log format from sample lines."""
        for line in sample_lines[:10]:
            line = line.strip()
            if not line:
                continue
            for fmt, pattern in LOG_PATTERNS.items():
                if re.match(pattern, line):
                    return fmt
        return 'unknown'
    
    def extract_severity(self, line: str) -> str:
        """Extract severity level from a log line."""
        line_upper = line.upper()
        
        # Check for common severity keywords
        if any(kw in line_upper for kw in ['CRITICAL', 'FATAL', 'EMERGENCY', 'PANIC']):
            return 'CRITICAL'
        elif any(kw in line_upper for kw in ['ERROR', 'ERR', 'FAIL', 'FAILED']):
            return 'ERROR'
        elif any(kw in line_upper for kw in ['WARN', 'WARNING']):
            return 'WARNING'
        elif any(kw in line_upper for kw in ['DEBUG', 'TRACE']):
            return 'DEBUG'
        else:
            return 'INFO'
    
    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Try to extract timestamp from log line."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        ]
        for pat in patterns:
            match = re.search(pat, line)
            if match:
                try:
                    ts_str = match.group(1)
                    for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', 
                               '%d/%b/%Y:%H:%M:%S', '%b %d %H:%M:%S']:
                        try:
                            return datetime.strptime(ts_str, fmt)
                        except:
                            continue
                except:
                    pass
        return None
    
    def read_logs(self, source: str, tail: int = None, since: str = None) -> List[str]:
        """Read logs from file or stdin."""
        lines = []
        
        if source == '-':
            lines = sys.stdin.readlines()
        else:
            path = Path(source)
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {source}")
            with open(path, 'r', errors='ignore') as f:
                lines = f.readlines()
        
        # Apply tail filter
        if tail:
            lines = lines[-tail:]
        
        # Apply time filter
        if since:
            since_dt = self._parse_since(since)
            if since_dt:
                filtered = []
                for line in lines:
                    ts = self.parse_timestamp(line)
                    if ts is None or ts >= since_dt:
                        filtered.append(line)
                lines = filtered
        
        return [l.strip() for l in lines if l.strip()]
    
    def _parse_since(self, since: str) -> Optional[datetime]:
        """Parse 'since' time specification (e.g., '1h', '30m', '2d')."""
        match = re.match(r'^(\d+)([smhd])$', since.lower())
        if match:
            value, unit = int(match.group(1)), match.group(2)
            units = {'s': 'seconds', 'm': 'minutes', 'h': 'hours', 'd': 'days'}
            delta = timedelta(**{units[unit]: value})
            return datetime.now() - delta
        return None
    
    def analyze_patterns(self, lines: List[str]) -> Dict[str, Any]:
        """Analyze log patterns and extract statistics."""
        severity_counts = Counter()
        errors = []
        timestamps = []
        
        for line in lines:
            severity = self.extract_severity(line)
            severity_counts[severity] += 1
            
            if severity in ['ERROR', 'CRITICAL']:
                errors.append(line[:200])  # Truncate long lines
            
            ts = self.parse_timestamp(line)
            if ts:
                timestamps.append(ts)
        
        # Calculate time range
        time_range = None
        if timestamps:
            time_range = {
                'start': min(timestamps).isoformat(),
                'end': max(timestamps).isoformat(),
                'duration_seconds': (max(timestamps) - min(timestamps)).total_seconds()
            }
        
        return {
            'total_lines': len(lines),
            'severity_counts': dict(severity_counts),
            'error_samples': errors[:10],
            'time_range': time_range,
            'log_format': self.detect_format(lines),
        }
    
    def ai_analyze(self, lines: List[str], query: str = None) -> str:
        """Use LLM to analyze logs."""
        # Prepare log sample (limit to avoid token overflow)
        sample = '\n'.join(lines[:100])
        if len(lines) > 100:
            sample += f"\n... ({len(lines) - 100} more lines)"
        
        # Get basic stats first
        stats = self.analyze_patterns(lines)
        
        system_prompt = """You are a log analysis expert. Analyze the provided logs and give clear, actionable insights.
Focus on:
- Errors and their root causes
- Patterns and anomalies
- Security concerns if any
- Performance issues
- Recommendations

Be concise but thorough. Use bullet points for clarity."""

        if query:
            prompt = f"""Analyze these logs and answer this question: {query}

LOG STATISTICS:
- Total lines: {stats['total_lines']}
- Severity breakdown: {stats['severity_counts']}
- Log format: {stats['log_format']}

LOGS:
{sample}"""
        else:
            prompt = f"""Analyze these logs and provide insights:

LOG STATISTICS:
- Total lines: {stats['total_lines']}
- Severity breakdown: {stats['severity_counts']}
- Log format: {stats['log_format']}

LOGS:
{sample}

Provide:
1. Summary of what's happening
2. Key errors/issues found
3. Patterns detected
4. Recommendations"""

        return self.ollama.generate(prompt, system_prompt)
    
    def highlight_line(self, line: str) -> str:
        """Add color highlighting to a log line."""
        severity = self.extract_severity(line)
        color = SEVERITY_COLORS.get(severity, '')
        return f"{color}{line}{Colors.RESET}"


def generate_html_report(analysis: Dict, ai_response: str, lines: List[str]) -> str:
    """Generate an HTML report."""
    severity_html = ''.join(
        f'<span class="badge {k.lower()}">{k}: {v}</span>'
        for k, v in analysis['severity_counts'].items()
    )
    
    errors_html = ''.join(
        f'<div class="log-line error">{e}</div>'
        for e in analysis['error_samples'][:5]
    )
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Log Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin: 20px 0; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; margin: 4px; 
                 font-weight: bold; }}
        .critical {{ background: #dc3545; color: white; }}
        .error {{ background: #fd7e14; color: white; }}
        .warning {{ background: #ffc107; color: #333; }}
        .info {{ background: #28a745; color: white; }}
        .debug {{ background: #6c757d; color: white; }}
        .log-line {{ font-family: monospace; padding: 8px; margin: 4px 0; background: #f8f9fa; 
                    border-left: 4px solid #dc3545; overflow-x: auto; }}
        .ai-response {{ white-space: pre-wrap; line-height: 1.6; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>📊 Log Analysis Report</h1>
    <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
       Analyzed: {analysis['total_lines']} lines | Format: {analysis['log_format']}</p>
    
    <div class="card">
        <h2>📈 Severity Distribution</h2>
        {severity_html}
    </div>
    
    <div class="card">
        <h2>🤖 AI Analysis</h2>
        <div class="ai-response">{ai_response}</div>
    </div>
    
    <div class="card">
        <h2>🚨 Recent Errors</h2>
        {errors_html if errors_html else '<p>No errors found.</p>'}
    </div>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(
        description='🔍 AI-powered log analysis using local LLMs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/log/syslog --query "What errors occurred?"
  %(prog)s nginx.log --tail 100 --format json
  cat app.log | %(prog)s - --query "Find security issues"
  %(prog)s /var/log/auth.log --since 1h --output report.html
        """
    )
    
    parser.add_argument('logfile', help='Log file path or "-" for stdin')
    parser.add_argument('-q', '--query', help='Natural language query about the logs')
    parser.add_argument('-t', '--tail', type=int, help='Only analyze last N lines')
    parser.add_argument('-s', '--since', help='Analyze logs since (e.g., 1h, 30m, 2d)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'html'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--model', default='qwen2.5:3b', help='Ollama model to use')
    parser.add_argument('--host', default='http://localhost:11434', help='Ollama API host')
    parser.add_argument('--no-ai', action='store_true', help='Skip AI analysis, show stats only')
    parser.add_argument('--color', action='store_true', help='Force colored output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize Ollama client
    ollama = OllamaClient(host=args.host, model=args.model)
    analyzer = LogAnalyzer(ollama)
    
    # Check Ollama availability
    if not args.no_ai and not ollama.is_available():
        print(f"{Colors.RED}⚠ Ollama not available at {args.host}{Colors.RESET}", file=sys.stderr)
        print("Start Ollama or use --no-ai for stats only", file=sys.stderr)
        sys.exit(1)
    
    # Read and analyze logs
    try:
        lines = analyzer.read_logs(args.logfile, tail=args.tail, since=args.since)
    except FileNotFoundError as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    
    if not lines:
        print("No log lines to analyze.", file=sys.stderr)
        sys.exit(0)
    
    if args.verbose:
        print(f"{Colors.CYAN}Analyzing {len(lines)} log lines...{Colors.RESET}", file=sys.stderr)
    
    # Get analysis
    stats = analyzer.analyze_patterns(lines)
    ai_response = ""
    
    if not args.no_ai:
        if args.verbose:
            print(f"{Colors.CYAN}Running AI analysis with {args.model}...{Colors.RESET}", file=sys.stderr)
        ai_response = analyzer.ai_analyze(lines, args.query)
    
    # Format output
    if args.format == 'json':
        output = json.dumps({
            'statistics': stats,
            'ai_analysis': ai_response,
            'query': args.query,
            'model': args.model,
            'timestamp': datetime.now().isoformat(),
        }, indent=2)
    elif args.format == 'html':
        output = generate_html_report(stats, ai_response, lines)
    else:
        # Text format
        output_lines = [
            f"\n{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.RESET}",
            f"{Colors.BOLD}📊 LOG ANALYSIS REPORT{Colors.RESET}",
            f"{Colors.BOLD}═══════════════════════════════════════════════════════════{Colors.RESET}\n",
            f"{Colors.CYAN}📁 Source:{Colors.RESET} {args.logfile}",
            f"{Colors.CYAN}📏 Lines analyzed:{Colors.RESET} {stats['total_lines']}",
            f"{Colors.CYAN}📋 Log format:{Colors.RESET} {stats['log_format']}",
            "",
            f"{Colors.BOLD}📈 Severity Distribution:{Colors.RESET}",
        ]
        
        for sev, count in sorted(stats['severity_counts'].items()):
            color = SEVERITY_COLORS.get(sev, '')
            bar = '█' * min(count, 50)
            output_lines.append(f"  {color}{sev:10}{Colors.RESET} {bar} {count}")
        
        if stats['time_range']:
            output_lines.extend([
                "",
                f"{Colors.BOLD}⏰ Time Range:{Colors.RESET}",
                f"  Start: {stats['time_range']['start']}",
                f"  End:   {stats['time_range']['end']}",
            ])
        
        if ai_response:
            output_lines.extend([
                "",
                f"{Colors.BOLD}🤖 AI Analysis ({args.model}):{Colors.RESET}",
                f"{Colors.BOLD}───────────────────────────────────────────────────────────{Colors.RESET}",
                ai_response,
            ])
        
        if stats['error_samples']:
            output_lines.extend([
                "",
                f"{Colors.BOLD}🚨 Sample Errors:{Colors.RESET}",
                f"{Colors.BOLD}───────────────────────────────────────────────────────────{Colors.RESET}",
            ])
            for err in stats['error_samples'][:5]:
                output_lines.append(f"  {Colors.RED}• {err[:100]}{Colors.RESET}")
        
        output = '\n'.join(output_lines)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"{Colors.GREEN}✓ Report saved to {args.output}{Colors.RESET}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
