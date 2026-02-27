#!/usr/bin/env python3
"""
logparser.py — Linux Log Parser
Parses common Linux log files and outputs structured JSON.

Usage:
    python logparser.py                  # interactive mode (prompts for input/output)
    python logparser.py --help           # show help menu
    python logparser.py -i <file>        # specify input file
    python logparser.py -i <file> -o <file>  # specify input and output file
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, IO, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
#  SHARED TYPES & HELPERS
# ══════════════════════════════════════════════════════════════════════════════

LogEntry = Dict[str, Any]
ParseResult = Dict[str, Any]


def make_result(file_path: str, log_type: str) -> ParseResult:
    """Return a fresh, empty ParseResult dict."""
    return {
        "file_path":   file_path,
        "log_type":    log_type,
        "parsed_at":   "",
        "total_lines": 0,
        "entries":     [],
    }


def make_entry(line_number: int, raw: str) -> LogEntry:
    """Return a minimal LogEntry dict for a raw log line."""
    return {
        "line_number": line_number,
        "timestamp":   None,
        "level":       None,
        "hostname":    None,
        "process":     None,
        "pid":         None,
        "message":     raw,
        "raw":         raw,
    }


def clean_entry(entry: LogEntry) -> LogEntry:
    """Strip keys whose value is None so they are absent from the JSON output."""
    return {k: v for k, v in entry.items() if v is not None}


# Keyword table for inferring log severity from message text
_LEVEL_KEYWORDS: List[Tuple[str, str]] = [
    ("emergency", "EMERGENCY"),
    ("emerg",     "EMERGENCY"),
    ("critical",  "CRITICAL"),
    ("crit",      "CRITICAL"),
    ("alert",     "ALERT"),
    ("fatal",     "FATAL"),
    ("error",     "ERROR"),
    ("warning",   "WARNING"),
    ("warn",      "WARNING"),
    ("notice",    "NOTICE"),
    ("info",      "INFO"),
    ("debug",     "DEBUG"),
    ("trace",     "TRACE"),
]


def detect_level(message: str) -> Optional[str]:
    """Return a severity level by scanning the message for known keywords."""
    lower = message.lower()
    for keyword, level in _LEVEL_KEYWORDS:
        if keyword in lower:
            return level
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  BASE PARSER
# ══════════════════════════════════════════════════════════════════════════════

class BaseParser(ABC):
    """Abstract base class that every log-format parser must implement."""

    @abstractmethod
    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        ...


# ══════════════════════════════════════════════════════════════════════════════
#  SYSLOG PARSER  (/var/log/syslog, /var/log/auth.log)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Format:  Jan  1 00:00:00 hostname process[pid]: message

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"   # timestamp
    r"\s+(\S+)"                                         # hostname
    r"\s+(\S+?)(?:\[(\d+)\])?:\s+"                     # process[pid]:
    r"(.*)$"                                            # message
)


def _parse_syslog_style(file: IO[str], file_path: str, log_type: str) -> ParseResult:
    """Shared parsing logic for all syslog-formatted log files."""
    result = make_result(file_path, log_type)

    for line_number, raw_line in enumerate(file, start=1):
        line = raw_line.rstrip("\n")
        entry = make_entry(line_number, line)

        m = _SYSLOG_RE.match(line)
        if m:
            entry["timestamp"] = m.group(1).strip()
            entry["hostname"] = m.group(2)
            entry["process"] = m.group(3)
            entry["pid"] = m.group(4)
            entry["message"] = m.group(5)
            entry["level"] = detect_level(m.group(5))

        result["entries"].append(clean_entry(entry))

    result["total_lines"] = len(result["entries"])
    return result


class SyslogParser(BaseParser):
    """Parses /var/log/syslog."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        return _parse_syslog_style(file, file_path, "syslog")


class AuthLogParser(BaseParser):
    """Parses /var/log/auth.log."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        return _parse_syslog_style(file, file_path, "auth.log")


# ══════════════════════════════════════════════════════════════════════════════
#  KERNEL PARSER  (/var/log/kern.log, dmesg output)
# ══════════════════════════════════════════════════════════════════════════════
#
#  dmesg format : [   0.000000] message
#  syslog format: Jan  1 00:00:00 hostname kernel[pid]: message

_DMESG_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s+(.*)$")
_KERN_LEVEL_RE = re.compile(r"^<(\d)>\s*(.*)$")

_KERN_LEVEL_MAP = {
    "0": "EMERGENCY",
    "1": "ALERT",
    "2": "CRITICAL",
    "3": "ERROR",
    "4": "WARNING",
    "5": "NOTICE",
    "6": "INFO",
    "7": "DEBUG",
}


class KernelLogParser(BaseParser):
    """
    Parses /var/log/kern.log and raw dmesg output.
    Auto-detects dmesg vs syslog-style by inspecting the first non-empty line.
    """

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        lines = [line.rstrip("\n") for line in file]

        is_dmesg = any(
            _DMESG_RE.match(line) for line in lines if line.strip()
        )

        if not is_dmesg:
            return _parse_syslog_style(
                io.StringIO("\n".join(lines)), file_path, "kern.log"
            )

        result = make_result(file_path, "kern.log")

        for line_number, line in enumerate(lines, start=1):
            entry = make_entry(line_number, line)
            entry["process"] = "kernel"

            m = _DMESG_RE.match(line)
            if m:
                entry["timestamp"] = m.group(1)
                msg = m.group(2)

                lm = _KERN_LEVEL_RE.match(msg)
                if lm:
                    entry["level"] = _KERN_LEVEL_MAP.get(
                        lm.group(1), "UNKNOWN")
                    msg = lm.group(2).strip()

                entry["message"] = msg
            else:
                entry["level"] = detect_level(line)
                entry["process"] = None

            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  DPKG PARSER  (/var/log/dpkg.log)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Format:  2024-01-01 00:00:00 status installed pkg:arch version

_DPKG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$"
)

_DPKG_ACTION_LEVEL = {
    "error":    "ERROR",
    "warning":  "WARNING",
    "purge":    "WARNING",
    "conffile": "WARNING",
    "trigproc": "DEBUG",
}


class DpkgLogParser(BaseParser):
    """Parses /var/log/dpkg.log."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        result = make_result(file_path, "dpkg.log")

        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.rstrip("\n")
            entry = make_entry(line_number, line)

            if line.strip():
                m = _DPKG_RE.match(line)
                if m:
                    action = m.group(2)
                    entry["timestamp"] = m.group(1)
                    entry["process"] = action
                    entry["level"] = _DPKG_ACTION_LEVEL.get(
                        action.lower(), "INFO")
                    entry["message"] = m.group(3)

            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  APT PARSER  (/var/log/apt/history.log)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Format:  Start-Date: 2024-01-01  00:00:00  (key-value style)

_APT_DATE_RE = re.compile(
    r"^(Start-Date|End-Date):\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})$"
)


class AptLogParser(BaseParser):
    """Parses /var/log/apt/history.log and term.log."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        result = make_result(file_path, "apt.log")
        current_timestamp = None

        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.rstrip("\n")
            entry = make_entry(line_number, line)

            if not line.strip():
                entry["timestamp"] = None
                entry["level"] = None
                result["entries"].append(clean_entry(entry))
                continue

            m = _APT_DATE_RE.match(line)
            if m:
                current_timestamp = m.group(2)

            entry["timestamp"] = current_timestamp
            entry["level"] = "INFO"

            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  NGINX PARSER  (access + error logs)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Access: 127.0.0.1 - user [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "UA"
#  Error : 2024/01/01 00:00:00 [error] 1234#0: *1 message

_ACCESS_RE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+|-)'
    r'\s+"([^"]*)"\s+"([^"]*)"'
)

_NGINX_ERROR_RE = re.compile(
    r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\S+):\s+(.*)$"
)


def _http_level(status: str) -> str:
    if status.startswith(("2", "3")):
        return "INFO"
    if status.startswith("4"):
        return "WARNING"
    if status.startswith("5"):
        return "ERROR"
    return "UNKNOWN"


def _is_error_log(file_path: str) -> bool:
    return "error" in os.path.basename(file_path).lower()


class NginxLogParser(BaseParser):
    """Parses Nginx access and error logs."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        error_mode = _is_error_log(file_path)
        log_type = "nginx-error.log" if error_mode else "nginx-access.log"
        result = make_result(file_path, log_type)

        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.rstrip("\n")
            entry = make_entry(line_number, line)
            entry["process"] = "nginx"

            if error_mode:
                m = _NGINX_ERROR_RE.match(line)
                if m:
                    entry["timestamp"] = m.group(1)
                    entry["level"] = m.group(2).upper()
                    entry["pid"] = m.group(3)
                    entry["message"] = m.group(4)
            else:
                m = _ACCESS_RE.match(line)
                if m:
                    entry["hostname"] = m.group(1)
                    entry["timestamp"] = m.group(3)
                    entry["message"] = f"{m.group(4)} -> {m.group(5)}"
                    entry["level"] = _http_level(m.group(5))

            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══
#  APACHE PARSER  (access + error logs)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Access: same combined log format as Nginx
#  Error : [Tue Jan 01 00:00:00.000000 2024] [core:error] [pid 1234] message

_APACHE_ERROR_RE = re.compile(
    r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[pid\s+(\d+)\]\s+(.*)$"
)


class ApacheLogParser(BaseParser):
    """Parses Apache httpd access and error logs."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        error_mode = _is_error_log(file_path)
        log_type   = "apache-error.log" if error_mode else "apache-access.log"
        result     = make_result(file_path, log_type)

        for line_number, raw_line in enumerate(file, start=1):
            line             = raw_line.rstrip("\n")
            entry            = make_entry(line_number, line)
            entry["process"] = "apache"

            if error_mode:
                m = _APACHE_ERROR_RE.match(line)
                if m:
                    entry["timestamp"] = m.group(1)
                    parts = m.group(2).split(":", 1)
                    if len(parts) == 2:
                        entry["process"] = parts[0]
                        entry["level"]   = parts[1].upper()
                    else:
                        entry["level"]   = m.group(2).upper()
                    entry["pid"]     = m.group(3)
                    entry["message"] = m.group(4)
            else:
                m = _ACCESS_RE.match(line)
                if m:
                    entry["hostname"]  = m.group(1)
                    entry["timestamp"] = m.group(3)
                    entry["message"]   = f"{m.group(4)} -> {m.group(5)}"
                    entry["level"]     = _http_level(m.group(5))

            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  GENERIC FALLBACK PARSER
# ══════════════════════════════════════════════════════════════════════════════
#
#  Attempts to extract an ISO-8601 timestamp and infer a severity level.

_ISO_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)"
)


class GenericLogParser(BaseParser):
    """Fallback parser for any unrecognised log format."""

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        result = make_result(file_path, "generic")

        for line_number, raw_line in enumerate(file, start=1):
            line  = raw_line.rstrip("\n")
            entry = make_entry(line_number, line)

            m = _ISO_TS_RE.match(line)
            if m:
                entry["timestamp"] = m.group(1)
                entry["message"]   = m.group(2)

            entry["level"] = detect_level(entry["message"])
            result["entries"].append(clean_entry(entry))

        result["total_lines"] = len(result["entries"])
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  FORMAT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_parser(file_path: str) -> BaseParser:
    """Inspect the filename and return the most appropriate parser."""
    base = os.path.basename(file_path).lower()

    if base == "syslog" or base.startswith("syslog"):
        return SyslogParser()
    if base == "auth.log" or base.startswith("auth"):
        return AuthLogParser()
    if base == "kern.log" or base.startswith("kern"):
        return KernelLogParser()
    if base == "dpkg.log" or base.startswith("dpkg"):
        return DpkgLogParser()
    if "apt" in base:
        return AptLogParser()
    if "nginx" in base or base.startswith("access") or base.startswith("error"):
        return NginxLogParser()
    if "apache" in base or "httpd" in base:
        return ApacheLogParser()

    return GenericLogParser()


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def validate_input_file(path: str) -> str:
    """Resolve and validate an input file path. Returns the absolute path."""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    if not os.path.isfile(abs_path):
        raise ValueError(f"Path is a directory, not a file: {abs_path}")
    if not os.access(abs_path, os.R_OK):
        raise PermissionError(f"No read permission for: {abs_path}")
    return abs_path


def validate_output_file(path: str) -> str:
    """Resolve and validate an output file path. Returns the absolute path."""
    abs_path   = os.path.abspath(path)
    parent_dir = os.path.dirname(abs_path)
    if not os.path.exists(parent_dir):
        raise FileNotFoundError(f"Output directory does not exist: {parent_dir}")
    if os.path.isdir(abs_path):
        raise ValueError(f"Output path is a directory: {abs_path}")
    return abs_path


def prompt_input_file() -> str:
    """Interactively prompt the user for a valid input file path."""
    while True:
        try:
            path = input("Enter the path of the log file to parse: ").strip()
            if not path:
                print("  Please enter a file path.\n")
                continue
            return validate_input_file(path)
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            print(f"  Error: {exc}\n")


def prompt_output_file() -> str:
    """Interactively prompt the user for a valid output file path."""
    while True:
        try:
            path = input("Enter the path to save the JSON output:  ").strip()
            if not path:
                print("  Please enter a file path.\n")
                continue
            return validate_output_file(path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"  Error: {exc}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  HELP MENU
# ══════════════════════════════════════════════════════════════════════════════

HELP_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║              Linux Log Parser v1.0.0  —  Help Menu              ║
╚══════════════════════════════════════════════════════════════════╝

DESCRIPTION
  Parses common Linux log files and outputs structured JSON both to
  the terminal and to a file of your choice.

USAGE
  python logparser.py                        Interactive mode
  python logparser.py -i <input>             Specify input file
  python logparser.py -i <input> -o <output> Specify input and output
  python logparser.py --help                 Show this help menu

OPTIONS
  -i, --input   <path>   Path to the log file you want to parse.
                         Accepts relative or absolute paths.
  -o, --output  <path>   Path where the JSON output will be saved.
                         Defaults to <input_filename>.json in the
                         current directory if not provided.
  -h, --help             Show this help menu and exit.

SUPPORTED LOG FORMATS
  ┌─────────────────────────────┬──────────────────────┐
  │ File / Pattern              │ Parser               │
  ├─────────────────────────────┼──────────────────────┤
  │ syslog, syslog.*            │ Syslog               │
  │ auth.log, auth.*            │ Auth log             │
  │ kern.log, kern.*            │ Kernel / dmesg       │
  │ dpkg.log, dpkg.*            │ dpkg                 │
  │ *apt*                       │ APT history          │
  │ *nginx*, access.*, error.*  │ Nginx                │
  │ *apache*, *httpd*           │ Apache httpd         │
  │ (anything else)             │ Generic fallback     │
  └─────────────────────────────┴──────────────────────┘

JSON OUTPUT FIELDS
  file_path    Absolute path of the parsed log file
  log_type     Detected log format
  parsed_at    UTC timestamp of when parsing was performed
  total_lines  Total number of lines in the file
  entries[]    Array of parsed log entries, each containing:
    line_number  Line number in the original file
    timestamp    Extracted timestamp (if detected)
    level        Severity level  (ERROR / WARNING / INFO / DEBUG …)
    hostname     Source hostname (if present)
    process      Process or service name (if present)
    pid          Process ID (if present)
    message      Parsed log message
    raw          Original unmodified line

EXAMPLES
  python logparser.py -i /var/log/syslog -o /tmp/syslog.json
  python logparser.py -i /var/log/auth.log
  python logparser.py -i ./kern.log -o ./output/kern.json
  python logparser.py                          # interactive prompts
"""


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="logparser.py",
        description="Linux Log Parser — parses log files and outputs JSON",
        add_help=False,   # we print our own help
    )
    ap.add_argument("-i", "--input",  metavar="<path>", help="Input log file path")
    ap.add_argument("-o", "--output", metavar="<path>", help="Output JSON file path")
    ap.add_argument("-h", "--help",   action="store_true", help="Show help and exit")
    return ap


def default_output_path(input_path: str) -> str:
    """Derive a sensible default output filename from the input filename."""
    base    = os.path.basename(input_path)
    stem    = base if "." not in base else base.rsplit(".", 1)[0]
    return os.path.join(os.getcwd(), f"{stem}_parsed.json")


def main() -> None:
    ap   = build_arg_parser()
    args = ap.parse_args()

    # ── Help ──────────────────────────────────────────────────────────────────
    if args.help:
        print(HELP_TEXT)
        sys.exit(0)

    print("=" * 44)
    print("        Linux Log Parser v1.0.0          ")
    print("=" * 44)
    print()

    # ── Resolve input file ────────────────────────────────────────────────────
    if args.input:
        try:
            input_path = validate_input_file(args.input)
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        input_path = prompt_input_file()

    # ── Resolve output file ───────────────────────────────────────────────────
    if args.output:
        try:
            output_path = validate_output_file(args.output)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # If no -o flag was given, prompt only when also in interactive mode
        if not args.input:
            output_path = prompt_output_file()
        else:
            output_path = default_output_path(input_path)
            print(f"No output file specified — defaulting to: {output_path}")

    print(f"\nInput  : {input_path}")
    print(f"Output : {output_path}")
    print("\nParsing... please wait.\n")

    # ── Parse ─────────────────────────────────────────────────────────────────
    parser = detect_parser(input_path)

    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
            result = parser.parse(fh, input_path)
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        sys.exit(1)

    result["parsed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    json_output = json.dumps(result, indent=2, ensure_ascii=False)

    # ── Write output file ─────────────────────────────────────────────────────
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(json_output)
            fh.write("\n")
    except OSError as exc:
        print(f"Error writing output file: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Print to terminal ─────────────────────────────────────────────────────
    print(json_output)

    print(f"\n Done. Results saved to : {output_path}")
    print(f"  Total lines parsed     : {result['total_lines']}")


if __name__ == "__main__":
    main()
