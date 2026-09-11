#!/usr/bin/env python3
"""
logparser.py — Linux Log Parser

Parses common Linux log files into structured JSON, JSON Lines, or CSV, with
content-based format detection, ISO 8601 timestamp normalisation, filtering,
and a summary report. Standard library only (Python 3.8+).

Usage:
    python logparser.py                                  # interactive mode
    python logparser.py /var/log/syslog                  # parse a file
    python logparser.py -i <file> -o <file>              # explicit input/output
    python logparser.py /var/log/auth.log* --level warning
    journalctl -o json | python logparser.py -o -        # stdin -> stdout
    python logparser.py --help                           # full help menu
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import itertools
import json
import os
import re
import sys
import tempfile
from abc import ABC, abstractmethod
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import (IO, Any, Callable, Dict, Iterable, Iterator, List, Optional,
                    Sequence, Tuple, Type)

__version__ = "2.0.0"


# ══════════════════════════════════════════════════════════════════════════════
#  SHARED TYPES & HELPERS
# ══════════════════════════════════════════════════════════════════════════════

LogEntry = Dict[str, Any]
ParseResult = Dict[str, Any]


def make_entry(line_number: int, raw: str) -> LogEntry:
    """
    Return a fresh LogEntry. Keys starting with "_" are internal bookkeeping
    and are stripped by clean_entry() before output.
    """
    return {
        "line_number":   line_number,
        "timestamp":     None,     # timestamp exactly as written in the log
        "timestamp_iso": None,     # normalised ISO 8601 form
        "level":         None,
        "hostname":      None,
        "process":       None,
        "pid":           None,
        "message":       raw,
        "fields":        {},       # format-specific structured details
        "raw":           raw,
        "_dt":           None,     # datetime object, used for filtering
        "_matched":      False,    # did the parser recognise this line?
    }


def clean_entry(entry: LogEntry) -> LogEntry:
    """Drop internal keys, None values, and empty `fields` for output."""
    return {
        k: v for k, v in entry.items()
        if v is not None and not k.startswith("_") and not (k == "fields" and not v)
    }


def set_timestamp(entry: LogEntry, raw_ts: str, dt: Optional[datetime]) -> None:
    entry["timestamp"] = raw_ts
    if dt is not None:
        entry["timestamp_iso"] = dt.isoformat()
        entry["_dt"] = dt


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dash_to_none(value: Optional[str]) -> Optional[str]:
    return None if value in (None, "", "-") else value


def to_aware(dt: datetime) -> datetime:
    """Treat naive datetimes as local time so they can be compared with aware ones."""
    if dt.tzinfo is not None:
        return dt
    try:
        return dt.astimezone()
    except (OverflowError, OSError, ValueError):
        return dt.replace(tzinfo=timezone.utc)


def entry_datetime(entry: LogEntry) -> Optional[datetime]:
    """The entry's timestamp as an aware datetime (computed once, then cached)."""
    aware = entry.get("_aware")
    if aware is None and entry.get("_dt") is not None:
        aware = entry["_aware"] = to_aware(entry["_dt"])
    return aware


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ══════════════════════════════════════════════════════════════════════════════
#  SEVERITY LEVELS
# ══════════════════════════════════════════════════════════════════════════════

LEVELS: Tuple[str, ...] = (
    "TRACE", "DEBUG", "INFO", "NOTICE", "WARNING",
    "ERROR", "CRITICAL", "ALERT", "EMERGENCY",
)
LEVEL_RANK: Dict[str, int] = {name: rank for rank, name in enumerate(LEVELS)}
LEVEL_RANK["FATAL"] = LEVEL_RANK["CRITICAL"]

SYSLOG_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

SYSLOG_FACILITY = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp",
    "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)

_LEVEL_ALIASES = {
    "emerg": "EMERGENCY", "emergency": "EMERGENCY", "panic": "EMERGENCY",
    "alert": "ALERT",
    "crit": "CRITICAL", "critical": "CRITICAL",
    "fatal": "FATAL",
    "err": "ERROR", "error": "ERROR", "severe": "ERROR",
    "warn": "WARNING", "warning": "WARNING",
    "notice": "NOTICE",
    "info": "INFO", "information": "INFO", "informational": "INFO",
    "debug": "DEBUG",
    "trace": "TRACE",
}

# Numeric levels used by pino / bunyan style JSON loggers
_JSON_NUMERIC_LEVELS = {10: "TRACE", 20: "DEBUG",
                        30: "INFO", 40: "WARNING", 50: "ERROR", 60: "FATAL"}


def normalize_level(value: Any) -> Optional[str]:
    """Map level names/numbers from any format onto one canonical vocabulary."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = int(value)
        if 0 <= number <= 7:
            return SYSLOG_SEVERITY[number]
        return _JSON_NUMERIC_LEVELS.get(number)
    text = str(value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return normalize_level(int(text))
    if text in _LEVEL_ALIASES:
        return _LEVEL_ALIASES[text]
    if re.fullmatch(r"trace\d", text):          # Apache trace1 … trace8
        return "TRACE"
    return text.upper()


# Whole-word keywords used to *infer* a level from free text. Whole words matter:
# the old substring approach tagged "0 errors" as ERROR and "information" as INFO.
_LEVEL_KEYWORD_RE = re.compile(
    r"\b(emerg|emergency|panic|alert|crit|critical|fatal|error|failed|failure|"
    r"warn|warning|denied|notice|info|debug|trace)\b",
    re.IGNORECASE,
)
_KEYWORD_LEVEL = {
    "emerg": "EMERGENCY", "emergency": "EMERGENCY", "panic": "EMERGENCY",
    "alert": "ALERT", "crit": "CRITICAL", "critical": "CRITICAL", "fatal": "FATAL",
    "error": "ERROR", "failed": "ERROR", "failure": "ERROR",
    "warn": "WARNING", "warning": "WARNING", "denied": "WARNING",
    "notice": "NOTICE", "info": "INFO", "debug": "DEBUG", "trace": "TRACE",
}


def detect_level(message: str) -> Optional[str]:
    """Infer severity from message text; the most severe keyword found wins."""
    best, best_rank = None, -1
    for match in _LEVEL_KEYWORD_RE.finditer(message):
        level = _KEYWORD_LEVEL[match.group(1).lower()]
        if LEVEL_RANK[level] > best_rank:
            best, best_rank = level, LEVEL_RANK[level]
    return best


# ══════════════════════════════════════════════════════════════════════════════
#  TIMESTAMPS
# ══════════════════════════════════════════════════════════════════════════════
#
#  Month names are mapped by hand rather than with strptime("%b") so parsing
#  doesn't depend on the machine's locale.

_MONTHS = {
    name: number for number, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun",
         "jul", "aug", "sep", "oct", "nov", "dec"),
        start=1,
    )
}


def _month(name: str) -> Optional[int]:
    return _MONTHS.get(name[:3].lower())


def _micro(fraction: Optional[str]) -> int:
    return int((fraction or "0")[:6].ljust(6, "0"))


def _tz_from_offset(text: Optional[str]) -> Optional[timezone]:
    if not text:
        return None
    text = text.strip()
    if text.upper() == "Z":
        return timezone.utc
    sign = -1 if text.startswith("-") else 1
    digits = text.lstrip("+-").replace(":", "")
    if len(digits) != 4 or not digits.isdigit():
        return None
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))


def _safe_datetime(*args: int, tzinfo: Optional[timezone] = None) -> Optional[datetime]:
    try:
        return datetime(*args, tzinfo=tzinfo)
    except (ValueError, OverflowError):
        return None


_ISO_RE = re.compile(
    r"^(\d{4})[-/](\d{2})[-/](\d{2})[T\s]+(\d{2}):(\d{2})(?::(\d{2}))?"
    r"(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)


def parse_iso_timestamp(text: str) -> Optional[datetime]:
    """ISO 8601-ish: 2024-01-31T14:00:00.123+02:00, 2024/01/31 14:00:00, 2024-01-31 14:00:00,123"""
    m = _ISO_RE.match(text.strip())
    if not m:
        return None
    year, month, day, hour, minute, second, fraction, offset = m.groups()
    try:
        tzinfo = _tz_from_offset(offset)
    except ValueError:
        return None
    return _safe_datetime(int(year), int(month), int(day), int(hour), int(minute),
                          int(second or 0), _micro(fraction), tzinfo=tzinfo)


_CLF_TS_RE = re.compile(
    r"^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*([+-]\d{4})?$")


def parse_clf_timestamp(text: str) -> Optional[datetime]:
    """Common Log Format: 10/Oct/2024:13:55:36 +0000"""
    m = _CLF_TS_RE.match(text.strip())
    if not m or _month(m.group(2)) is None:
        return None
    try:
        tzinfo = _tz_from_offset(m.group(8))
    except ValueError:
        return None
    return _safe_datetime(int(m.group(3)), _month(m.group(2)), int(m.group(1)), int(m.group(4)),
                          int(m.group(5)), int(m.group(6)), _micro(m.group(7)), tzinfo=tzinfo)


_CTIME_RE = re.compile(
    r"^(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(\d{4})$")


def parse_ctime_timestamp(text: str) -> Optional[datetime]:
    """ctime style: Tue Oct 10 13:55:36.123456 2024 (Apache errors, dmesg -T)"""
    m = _CTIME_RE.match(text.strip())
    if not m or _month(m.group(1)) is None:
        return None
    return _safe_datetime(int(m.group(7)), _month(m.group(1)), int(m.group(2)), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), _micro(m.group(6)))


_BSD_TS_RE = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$")


class TimestampResolver:
    """
    Resolves traditional syslog timestamps ("Jan  5 10:00:00"), which carry no
    year. The year is taken from `fixed_year` if given; otherwise it's inferred
    relative to `reference` (normally the file's modification time), stepping
    back a year when needed so a December entry in a file last written in
    January lands in the previous year.
    """

    def __init__(self, reference: Optional[datetime] = None, fixed_year: Optional[int] = None):
        self.reference = reference or datetime.now()
        self.fixed_year = fixed_year

    def bsd(self, text: str) -> Optional[datetime]:
        m = _BSD_TS_RE.match(text.strip())
        if not m or _month(m.group(1)) is None:
            return None
        parts = (_month(m.group(1)), int(m.group(2)), int(m.group(3)),
                 int(m.group(4)), int(m.group(5)), _micro(m.group(6)))
        if self.fixed_year:
            return _safe_datetime(self.fixed_year, *parts)
        limit = self.reference + timedelta(days=1)
        for year in range(self.reference.year, self.reference.year - 5, -1):
            # also skips Feb 29 in non-leap years
            dt = _safe_datetime(year, *parts)
            if dt is not None and dt <= limit:
                return dt
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION EVENT EXTRACTION  (used by syslog-style and journal parsers)
# ══════════════════════════════════════════════════════════════════════════════

AUTH_PROCESSES = frozenset({
    "sshd", "sshd-session", "sudo", "su", "login", "passwd", "chpasswd", "chage",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd",
    "systemd-logind", "cron", "polkitd", "pkexec",
})

AUTH_FAILURE_EVENTS = frozenset({
    "login_failed", "invalid_user", "auth_failure", "max_auth_attempts",
    "sudo_denied", "su_failed",
})

_SSH_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("login_success", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("login_failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("max_auth_attempts", re.compile(
        r"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
        r"(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")),
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?")),
    ("connection_closed", re.compile(
        r"^Connection closed by (?:(?:authenticating|invalid) user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)")),
    ("disconnected", re.compile(
        r"^Disconnected from (?:(?:authenticating|invalid) )?(?:user (?P<user>\S+) )?(?P<ip>\S+) port (?P<port>\d+)")),
)

_PAM_RE = re.compile(
    r"pam_unix\((?P<service>[^:)]+):(?P<type>\w+)\):\s*(?P<rest>.*)$")
_PAM_SESSION_RE = re.compile(
    r"^session (?P<state>opened|closed) for user (?P<user>[^\s(]+)")
_PAM_PASSWORD_RE = re.compile(r"^password changed for (?P<user>\S+)")
_KV_RE = re.compile(r"(\w+)=(\S*)")
_SU_RE = re.compile(
    r"^(?P<failed>FAILED SU )?\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_ACCOUNT_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("user_created", re.compile(r"^new user: name=(?P<user>[^,]+),")),
    ("group_created", re.compile(r"^new group: name=(?P<group>[^,]+),")),
    ("user_deleted", re.compile(r"^delete user '(?P<user>[^']+)'")),
    ("password_changed", re.compile(r"^password changed for (?P<user>\S+)")),
)


def _extract_auth_fields(process: str, message: str) -> Optional[Dict[str, Any]]:
    if process in ("sshd", "sshd-session"):
        for event, pattern in _SSH_PATTERNS:
            m = pattern.match(message)
            if m:
                g = m.groupdict()
                fields: Dict[str, Any] = {"event": event}
                if g.get("user"):
                    fields["user"] = g["user"]
                if g.get("ip"):
                    fields["source_ip"] = g["ip"]
                if g.get("port"):
                    fields["port"] = int(g["port"])
                if g.get("method"):
                    fields["auth_method"] = g["method"]
                if g.get("invalid"):
                    fields["invalid_user"] = True
                return fields

    pam = _PAM_RE.search(message)
    if pam:
        rest = pam.group("rest")
        base = {"service": pam.group("service")}
        session = _PAM_SESSION_RE.match(rest)
        if session:
            return {"event": f"session_{session.group('state')}", "user": session.group("user"), **base}
        if rest.startswith("authentication failure"):
            kv = dict(_KV_RE.findall(rest))
            fields = {"event": "auth_failure", **base}
            if kv.get("user"):
                fields["user"] = kv["user"]
            if kv.get("rhost"):
                fields["source_ip"] = kv["rhost"]
            return fields
        pw = _PAM_PASSWORD_RE.match(rest)
        if pw:
            return {"event": "password_changed", "user": pw.group("user"), **base}

    if process == "sudo" and "COMMAND=" in message:
        head, command = message.split("COMMAND=", 1)
        user, _, detail = head.strip().partition(" : ")
        fields = {"user": user.strip(), "command": command.strip()}
        reasons = []
        for part in (p.strip() for p in detail.split(";")):
            if not part:
                continue
            key, sep, value = part.partition("=")
            if sep and key.isupper():
                fields[{"TTY": "tty", "PWD": "cwd", "USER": "run_as"}.get(
                    key, key.lower())] = value
            else:
                reasons.append(part)
        if reasons:
            fields["reason"] = "; ".join(reasons)
        fields["event"] = "sudo_denied" if reasons else "sudo_command"
        return fields

    if process == "su":
        m = _SU_RE.match(message)
        if m:
            return {"event": "su_failed" if m.group("failed") else "su",
                    "user": m.group("user"), "run_as": m.group("target"), "tty": m.group("tty")}

    for event, pattern in _ACCOUNT_PATTERNS:
        m = pattern.match(message)
        if m:
            return {"event": event, **m.groupdict()}
    return None


def enrich_auth(entry: LogEntry) -> None:
    """Attach structured authentication details (logins, sudo, su, account changes)."""
    process = (entry.get("process") or "").lower()
    message = entry.get("message") or ""
    if process not in AUTH_PROCESSES and "pam_unix(" not in message:
        return
    fields = _extract_auth_fields(process, message)
    if not fields:
        return
    entry["fields"].update(fields)
    if entry["level"] is None:
        entry["level"] = "WARNING" if fields["event"] in AUTH_FAILURE_EVENTS else "INFO"


# ══════════════════════════════════════════════════════════════════════════════
#  BASE PARSER
# ══════════════════════════════════════════════════════════════════════════════

class BaseParser(ABC):
    """
    Every parser turns one line into at most one LogEntry. Parsers that need to
    combine several lines (e.g. APT transactions) buffer internally, return
    None until the group is complete, and emit leftovers from finish().
    """

    name = "base"               # value for --log-type
    log_type = "unknown"        # label written to the output
    description = ""
    basename_prefixes: Tuple[str, ...] = ()   # weak filename hint
    path_keywords: Tuple[str, ...] = ()       # strong filename hint

    def __init__(self, resolver: Optional[TimestampResolver] = None):
        self.resolver = resolver or TimestampResolver()
        self.lines_read = 0
        self.blank_lines = 0
        self.unparsed_lines = 0

    @classmethod
    def sniff(cls, line: str) -> bool:
        """Return True if `line` looks like this parser's format (used for auto-detection)."""
        return False

    @classmethod
    def hint_score(cls, file_path: str) -> int:
        lower = file_path.lower()
        if any(keyword in lower for keyword in cls.path_keywords):
            return 2
        base = os.path.basename(lower)
        if any(base.startswith(prefix) for prefix in cls.basename_prefixes):
            return 1
        return 0

    def prepare(self, sample: List[str]) -> None:
        """Optional hook: inspect the first lines of the file before parsing."""

    @abstractmethod
    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        ...

    def finish(self) -> Optional[LogEntry]:
        return None

    def iter_entries(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        """Stream entries one at a time, so large files never sit in memory."""
        for line_number, raw_line in enumerate(lines, start=1):
            self.lines_read = line_number
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                self.blank_lines += 1
                continue
            entry = self.parse_line(line_number, line)
            if entry is not None:
                yield self._count(entry)
        entry = self.finish()
        if entry is not None:
            yield self._count(entry)

    def _count(self, entry: LogEntry) -> LogEntry:
        if not entry["_matched"]:
            self.unparsed_lines += 1
        return entry

    def parse(self, file: IO[str], file_path: str) -> ParseResult:
        """Backwards-compatible, in-memory API from v1."""
        entries = [clean_entry(e) for e in self.iter_entries(file)]
        return {
            "file_path":   file_path,
            "log_type":    self.log_type,
            "parsed_at":   utc_now_iso(),
            "total_lines": self.lines_read,
            "entries":     entries,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  SYSLOG PARSER  (/var/log/syslog, /var/log/messages, …)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Traditional: Jan  1 00:00:00 hostname process[pid]: message
#  rsyslog ISO: 2024-01-01T00:00:00.123456+00:00 hostname process[pid]: message
#               (default on Debian 12+ and recent Ubuntu)
#  Either may be preceded by a <PRI> value.

_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<proc>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:"
    r"\s?(?P<msg>.*)$"
)
_KERNEL_UPTIME_RE = re.compile(r"^\[\s*(\d+\.\d+)\]\s?(.*)$")


class SyslogParser(BaseParser):
    name = "syslog"
    log_type = "syslog"
    description = "syslog / rsyslog (syslog, messages, daemon.log)"
    basename_prefixes = ("syslog", "messages", "daemon", "user.log")

    @classmethod
    def sniff(cls, line: str) -> bool:
        return _SYSLOG_RE.match(line) is not None

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        entry = make_entry(line_number, line)
        if not self._parse_syslog(entry, line):
            entry["level"] = detect_level(line)
        return entry

    def _parse_syslog(self, entry: LogEntry, line: str) -> bool:
        m = _SYSLOG_RE.match(line)
        if not m:
            return False
        ts = m.group("ts")
        dt = parse_iso_timestamp(
            ts) if ts[0].isdigit() else self.resolver.bsd(ts)
        set_timestamp(entry, ts, dt)
        entry["hostname"] = m.group("host")
        entry["process"] = m.group("proc")
        entry["pid"] = _to_int(m.group("pid"))
        entry["message"] = m.group("msg").strip()
        entry["_matched"] = True

        if m.group("pri") is not None:
            pri = int(m.group("pri"))
            entry["level"] = SYSLOG_SEVERITY[pri % 8]
            if pri // 8 < len(SYSLOG_FACILITY):
                entry["fields"]["facility"] = SYSLOG_FACILITY[pri // 8]

        if entry["process"].lower() == "kernel":
            km = _KERNEL_UPTIME_RE.match(entry["message"])
            if km:
                entry["fields"]["uptime_seconds"] = float(km.group(1))
                entry["message"] = km.group(2)

        enrich_auth(entry)
        if entry["level"] is None:
            entry["level"] = detect_level(entry["message"])
        return True


class AuthLogParser(SyslogParser):
    name = "auth"
    log_type = "auth.log"
    description = "auth.log / secure (SSH logins, sudo, su, PAM)"
    basename_prefixes = ("auth", "secure")

    @classmethod
    def sniff(cls, line: str) -> bool:
        m = _SYSLOG_RE.match(line)
        return bool(m) and (m.group("proc").lower() in AUTH_PROCESSES or "pam_unix(" in line)


# ══════════════════════════════════════════════════════════════════════════════
#  KERNEL PARSER  (/var/log/kern.log, dmesg output)
# ══════════════════════════════════════════════════════════════════════════════
#
#  dmesg      : [    0.000000] message
#  dmesg -r   : <6>[    0.000000] message
#  dmesg -x   : kern  :info  : [    0.000000] message
#  dmesg -T   : [Mon Jan  1 00:00:00 2024] message
#  kern.log   : syslog format with process "kernel"

_DMESG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?:(?P<facility>[a-z0-9]+)\s*:\s*(?P<level>[a-z]+)\s*:\s*)?"
    r"\[\s*(?P<ts>\d+\.\d+|\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\d{4})\]"
    r"\s?(?P<msg>.*)$"
)
_KERN_INLINE_LEVEL_RE = re.compile(r"^<([0-7])>\s*(.*)$")


class KernelLogParser(SyslogParser):
    name = "kern"
    log_type = "kern.log"
    description = "kern.log and dmesg output (plain, -r, -x, -T)"
    basename_prefixes = ("kern", "dmesg")

    @classmethod
    def sniff(cls, line: str) -> bool:
        if _DMESG_RE.match(line):
            return True
        m = _SYSLOG_RE.match(line)
        return bool(m) and m.group("proc").lower() == "kernel"

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        m = _DMESG_RE.match(line)
        if not m:
            return super().parse_line(line_number, line)

        entry = make_entry(line_number, line)
        entry["process"] = "kernel"
        entry["_matched"] = True

        ts = m.group("ts")
        if ts[0].isdigit():
            # seconds since boot, not wall-clock time
            entry["timestamp"] = ts
            entry["fields"]["uptime_seconds"] = float(ts)
        else:
            set_timestamp(entry, ts, parse_ctime_timestamp(ts))

        if m.group("pri") is not None:
            entry["level"] = SYSLOG_SEVERITY[int(m.group("pri")) % 8]
        elif m.group("level"):
            entry["level"] = normalize_level(m.group("level"))
        if m.group("facility"):
            entry["fields"]["facility"] = m.group("facility")

        message = m.group("msg")
        inline = _KERN_INLINE_LEVEL_RE.match(message)
        if inline:
            entry["level"] = entry["level"] or SYSLOG_SEVERITY[int(
                inline.group(1))]
            message = inline.group(2)
        entry["message"] = message.strip()
        entry["level"] = entry["level"] or detect_level(message)
        return entry


# ══════════════════════════════════════════════════════════════════════════════
#  DPKG PARSER  (/var/log/dpkg.log)
# ══════════════════════════════════════════════════════════════════════════════
#
#  2024-01-01 00:00:00 status installed pkg:arch version
#  2024-01-01 00:00:00 upgrade pkg:arch old-version new-version

_DPKG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>\S+)\s+(?P<rest>.*)$")
DPKG_ACTIONS = frozenset({
    "startup", "status", "install", "upgrade", "configure", "trigproc",
    "disappear", "remove", "purge", "conffile",
})
_DPKG_ACTION_LEVEL = {"purge": "WARNING",
                      "conffile": "WARNING", "trigproc": "DEBUG"}


def _split_package(spec: str) -> Dict[str, str]:
    name, _, arch = spec.partition(":")
    return {"package": name, "arch": arch} if arch else {"package": name}


class DpkgLogParser(BaseParser):
    name = "dpkg"
    log_type = "dpkg.log"
    description = "dpkg.log (package installs, upgrades, removals)"
    basename_prefixes = ("dpkg",)

    @classmethod
    def sniff(cls, line: str) -> bool:
        m = _DPKG_RE.match(line)
        return bool(m) and m.group("action") in DPKG_ACTIONS

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        entry = make_entry(line_number, line)
        m = _DPKG_RE.match(line)
        if not m:
            entry["level"] = detect_level(line)
            return entry

        action, rest = m.group("action"), m.group("rest")
        set_timestamp(entry, m.group("ts"), parse_iso_timestamp(m.group("ts")))
        entry["process"] = action
        entry["message"] = rest
        entry["level"] = _DPKG_ACTION_LEVEL.get(action.lower(), "INFO")
        entry["_matched"] = action in DPKG_ACTIONS

        parts = rest.split()
        fields: Dict[str, Any] = {"action": action}
        if action == "startup" and parts:
            fields["type"] = parts[0]
            if len(parts) > 1:
                fields["command"] = parts[1]
        elif action == "status" and len(parts) >= 2:
            fields["state"] = parts[0]
            fields.update(_split_package(parts[1]))
            if len(parts) > 2:
                fields["version"] = _dash_to_none(
                    parts[2].replace("<none>", ""))
        elif action == "conffile" and len(parts) >= 2:
            fields["file"], fields["decision"] = parts[0], parts[1]
        elif parts and action in DPKG_ACTIONS:
            fields.update(_split_package(parts[0]))
            if len(parts) > 1 and parts[1] != "<none>":
                fields["installed_version"] = parts[1]
            if len(parts) > 2 and parts[2] != "<none>":
                fields["available_version"] = parts[2]
        entry["fields"] = {k: v for k, v in fields.items() if v is not None}
        return entry


# ══════════════════════════════════════════════════════════════════════════════
#  APT PARSER  (/var/log/apt/history.log, /var/log/apt/term.log)
# ══════════════════════════════════════════════════════════════════════════════
#
#  history.log stanzas become ONE entry per transaction:
#     Start-Date: 2024-01-01  12:00:00
#     Commandline: apt install nginx
#     Install: nginx:amd64 (1.24.0-1), libfoo:amd64 (2.0, automatic)
#     End-Date: 2024-01-01  12:00:05
#
#  term.log output lines are emitted individually, timestamped from the
#  enclosing "Log started:" header.

_APT_FIELD_RE = re.compile(
    r"^(?P<key>[A-Z][A-Za-z]+(?:-[A-Z][A-Za-z]+)*):\s*(?P<value>.*)$")
_APT_TERM_RE = re.compile(
    r"^Log (?P<what>started|ended):\s+(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*$")
_APT_PKG_RE = re.compile(r"(?P<name>[^\s,()]+)\s+\((?P<info>[^)]*)\)")
_APT_PACKAGE_KEYS = ("Install", "Reinstall", "Upgrade",
                     "Downgrade", "Remove", "Purge")
_APT_HISTORY_KEYS = frozenset(
    _APT_PACKAGE_KEYS + ("Start-Date", "End-Date", "Commandline", "Requested-By", "Error"))


def _parse_apt_packages(value: str, key: str) -> List[Dict[str, Any]]:
    packages = []
    for m in _APT_PKG_RE.finditer(value):
        package: Dict[str, Any] = _split_package(m.group("name"))
        parts = [p.strip() for p in m.group("info").split(",") if p.strip()]
        versions = [p for p in parts if p != "automatic"]
        if key in ("Upgrade", "Downgrade") and len(versions) >= 2:
            package["old_version"], package["new_version"] = versions[0], versions[1]
        elif versions:
            package["version"] = versions[0]
        if "automatic" in parts:
            package["automatic"] = True
        packages.append(package)
    return packages


class AptLogParser(BaseParser):
    name = "apt"
    log_type = "apt.log"
    description = "APT history.log (grouped per transaction) and term.log"
    basename_prefixes = ("apt",)
    path_keywords = ("/apt/",)

    def __init__(self, resolver: Optional[TimestampResolver] = None):
        super().__init__(resolver)
        self._txn: Optional[Dict[str, Any]] = None
        self._session_ts: Optional[str] = None

    @classmethod
    def sniff(cls, line: str) -> bool:
        m = _APT_FIELD_RE.match(line)
        return bool(m and m.group("key") in _APT_HISTORY_KEYS) or bool(_APT_TERM_RE.match(line))

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        term = _APT_TERM_RE.match(line)
        if term:
            flushed = self._flush()
            self._session_ts = term.group("ts") if term.group(
                "what") == "started" else None
            return flushed

        field = _APT_FIELD_RE.match(line)
        key = field.group("key") if field else None

        if field and key == "Start-Date":
            flushed = self._flush()
            self._txn = {"line_number": line_number, "raw": [line],
                         "values": {key: field.group("value").strip()}}
            return flushed

        if field and self._txn is not None and key in _APT_HISTORY_KEYS:
            self._txn["raw"].append(line)
            self._txn["values"][key] = field.group("value").strip()
            return self._flush() if key == "End-Date" else None

        # term.log output (or a stray line outside any transaction)
        entry = make_entry(line_number, line)
        entry["process"] = "apt"
        if self._session_ts:
            set_timestamp(entry, self._session_ts,
                          parse_iso_timestamp(self._session_ts))
            entry["_matched"] = True
        entry["level"] = detect_level(line) or (
            "INFO" if self._session_ts else None)
        return entry

    def finish(self) -> Optional[LogEntry]:
        return self._flush()

    def _flush(self) -> Optional[LogEntry]:
        txn, self._txn = self._txn, None
        if txn is None:
            return None
        values = txn["values"]
        entry = make_entry(txn["line_number"], "\n".join(txn["raw"]))
        entry["process"] = "apt"
        entry["_matched"] = True

        start = values.get("Start-Date")
        if start:
            set_timestamp(entry, start, parse_iso_timestamp(start))

        fields: Dict[str, Any] = {"kind": "transaction"}
        if "Commandline" in values:
            fields["commandline"] = values["Commandline"]
        if "Requested-By" in values:
            rb = re.match(r"^(\S+)(?:\s+\((\d+)\))?", values["Requested-By"])
            if rb:
                fields["requested_by"] = rb.group(1)
                if rb.group(2):
                    fields["requested_by_uid"] = int(rb.group(2))
        packages = {k.lower(): _parse_apt_packages(
            values[k], k) for k in _APT_PACKAGE_KEYS if k in values}
        if packages:
            fields["packages"] = packages
        if "End-Date" in values:
            fields["end"] = values["End-Date"]
            end_dt = parse_iso_timestamp(values["End-Date"])
            if end_dt and entry["_dt"]:
                fields["duration_seconds"] = (
                    end_dt - entry["_dt"]).total_seconds()
        if "Error" in values:
            fields["error"] = values["Error"]

        entry["fields"] = fields
        entry["level"] = "ERROR" if "Error" in values else "INFO"
        counts = ", ".join(
            f"{action}: {len(pkgs)}" for action, pkgs in packages.items())
        base = fields.get("commandline", "apt transaction")
        entry["message"] = f"{base} ({counts})" if counts else base
        return entry


# ══════════════════════════════════════════════════════════════════════════════
#  WEB SERVER PARSERS  (Nginx, Apache — access + error logs)
# ══════════════════════════════════════════════════════════════════════════════
#
#  Access (common or combined format, escaped quotes allowed):
#    127.0.0.1 - user [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "UA"
#  Nginx error:
#    2024/01/01 00:00:00 [error] 1234#0: *1 message, client: 1.2.3.4, server: x
#  Apache error (2.2 and 2.4):
#    [Tue Jan 01 00:00:00.000000 2024] [core:error] [pid 1234:tid 5] [client 1.2.3.4:5] AH00126: msg

_QUOTED = r'(?:[^"\\]|\\.)*'
_ACCESS_RE = re.compile(
    r"^(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    rf'"(?P<request>{_QUOTED})"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
    rf'(?:\s+"(?P<referrer>{_QUOTED})"\s+"(?P<agent>{_QUOTED})")?'
)
_REQUEST_RE = re.compile(
    r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/\d(?:\.\d)?))?$")

_NGINX_ERROR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$"
)
_NGINX_CONTEXT_RE = re.compile(
    rf',\s(client|server|request|upstream|host|referrer): ("{_QUOTED}"|[^,]*)')

_APACHE_ERROR_RE = re.compile(
    r"^\[(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s+"
    r"\[(?:(?P<module>[^:\]]+):)?(?P<level>[^\]]+)\]\s+"
    r"(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\]\s*)?"
    r"(?P<msg>.*)$"
)
_APACHE_CLIENT_RE = re.compile(r"\[client ([^\]]+)\]\s*")
_APACHE_CODE_RE = re.compile(r"\b(AH\d{5})\b")


def _http_level(status: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    return "INFO"


class _WebServerParser(BaseParser):
    server = "web"
    error_re: "re.Pattern[str]" = _NGINX_ERROR_RE

    @classmethod
    def sniff(cls, line: str) -> bool:
        return bool(_ACCESS_RE.match(line) or cls.error_re.match(line))

    def prepare(self, sample: List[str]) -> None:
        errors = sum(1 for line in sample if self.error_re.match(line))
        access = sum(1 for line in sample if _ACCESS_RE.match(line))
        self.log_type = f"{self.server}-{'error' if errors >
                                         access else 'access'}.log"

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        entry = make_entry(line_number, line)
        entry["process"] = self.server
        if self._parse_error(entry, line) or self._parse_access(entry, line):
            entry["_matched"] = True
        else:
            entry["level"] = detect_level(line)
        return entry

    def _parse_error(self, entry: LogEntry, line: str) -> bool:
        raise NotImplementedError

    @staticmethod
    def _parse_access(entry: LogEntry, line: str) -> bool:
        m = _ACCESS_RE.match(line)
        if not m:
            return False
        status = int(m.group("status"))
        request = m.group("request")
        set_timestamp(entry, m.group("ts"), parse_clf_timestamp(m.group("ts")))
        entry["hostname"] = m.group("client")
        entry["message"] = f"{request} -> {status}"
        entry["level"] = _http_level(status)

        fields: Dict[str, Any] = {
            "kind": "access",
            "client_ip": m.group("client"),
            "remote_user": _dash_to_none(m.group("user")),
            "request": request,
            "status": status,
            "bytes": _to_int(m.group("bytes")),
            "referrer": _dash_to_none(m.group("referrer")),
            "user_agent": _dash_to_none(m.group("agent")),
        }
        rm = _REQUEST_RE.match(request)
        if rm:
            fields.update(rm.groupdict())
        entry["fields"] = {k: v for k, v in fields.items() if v is not None}
        return True


class NginxLogParser(_WebServerParser):
    name = "nginx"
    log_type = "nginx-access.log"
    description = "Nginx access and error logs"
    server = "nginx"
    error_re = _NGINX_ERROR_RE
    path_keywords = ("nginx",)
    basename_prefixes = ("access", "error")

    def _parse_error(self, entry: LogEntry, line: str) -> bool:
        m = _NGINX_ERROR_RE.match(line)
        if not m:
            return False
        set_timestamp(entry, m.group("ts"), parse_iso_timestamp(m.group("ts")))
        entry["level"] = normalize_level(m.group("level"))
        entry["pid"] = int(m.group("pid"))

        message = m.group("msg")
        fields: Dict[str, Any] = {"kind": "error", "tid": int(m.group("tid"))}
        if m.group("cid"):
            fields["connection_id"] = int(m.group("cid"))
        context = list(_NGINX_CONTEXT_RE.finditer(message))
        if context:
            for match in context:
                value = match.group(2)
                fields[match.group(1)] = value[1:-
                                               1] if value.startswith('"') else value
            message = message[:context[0].start()]
        entry["message"] = message.strip()
        entry["fields"] = fields
        return True


class ApacheLogParser(_WebServerParser):
    name = "apache"
    log_type = "apache-access.log"
    description = "Apache httpd access and error logs"
    server = "apache"
    error_re = _APACHE_ERROR_RE
    path_keywords = ("apache", "httpd")

    def _parse_error(self, entry: LogEntry, line: str) -> bool:
        m = _APACHE_ERROR_RE.match(line)
        if not m:
            return False
        set_timestamp(entry, m.group("ts"),
                      parse_ctime_timestamp(m.group("ts")))
        entry["level"] = normalize_level(m.group("level"))
        entry["pid"] = _to_int(m.group("pid"))

        fields: Dict[str, Any] = {"kind": "error"}
        if m.group("module"):
            entry["process"] = m.group("module")
            fields["module"] = m.group("module")
        if m.group("tid"):
            fields["tid"] = int(m.group("tid"))

        message = m.group("msg")
        client = _APACHE_CLIENT_RE.search(message)
        if client:
            fields["client"] = client.group(1)
            message = message[:client.start()] + message[client.end():]
        code = _APACHE_CODE_RE.search(message)
        if code:
            fields["error_code"] = code.group(1)
        entry["message"] = message.strip()
        entry["fields"] = fields
        return True


# ══════════════════════════════════════════════════════════════════════════════
#  JSON LINES PARSER  (journalctl -o json, structured application logs)
# ══════════════════════════════════════════════════════════════════════════════

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_JOURNAL_TS_KEYS = ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP")


def _json_timestamp(key: str, value: Any) -> Tuple[str, Optional[datetime]]:
    text = str(value)
    if key in _JOURNAL_TS_KEYS:
        micros = _to_int(value)
        return text, (_EPOCH + timedelta(microseconds=micros)) if micros is not None else None
    if isinstance(value, (int, float)) or re.fullmatch(r"\d+(?:\.\d+)?", text):
        number = float(value)
        for threshold, divisor in ((1e17, 1e9), (1e14, 1e6), (1e11, 1e3)):
            if number > threshold:        # nanoseconds / microseconds / milliseconds
                number /= divisor
                break
        try:
            return text, _EPOCH + timedelta(seconds=number)
        except OverflowError:
            return text, None
    return text, parse_iso_timestamp(text)


class JsonLogParser(BaseParser):
    name = "json"
    log_type = "json"
    description = "JSON Lines, incl. journalctl -o json"
    basename_prefixes = ("journal",)
    path_keywords = (".json",)

    _TS_KEYS = _JOURNAL_TS_KEYS + \
        ("@timestamp", "timestamp", "time", "ts", "datetime", "date")
    _LEVEL_KEYS = ("PRIORITY", "level", "severity",
                   "lvl", "loglevel", "log_level")
    _MESSAGE_KEYS = ("MESSAGE", "message", "msg", "log")
    _HOST_KEYS = ("_HOSTNAME", "hostname", "host")
    _PROCESS_KEYS = ("SYSLOG_IDENTIFIER", "_COMM", "process",
                     "service", "app", "logger", "name")
    _PID_KEYS = ("_PID", "SYSLOG_PID", "pid")

    @classmethod
    def sniff(cls, line: str) -> bool:
        stripped = line.lstrip()
        if not stripped.startswith("{"):
            return False
        try:
            return isinstance(json.loads(stripped), dict)
        except ValueError:
            return False

    def prepare(self, sample: List[str]) -> None:
        if any('"__REALTIME_TIMESTAMP"' in line for line in sample):
            self.log_type = "journal"

    @staticmethod
    def _pick(obj: Dict[str, Any], keys: Sequence[str]) -> Tuple[Optional[str], Any]:
        for key in keys:
            value = obj.get(key)
            if value not in (None, "") and not isinstance(value, (dict, list)) or (
                    key == "MESSAGE" and isinstance(value, list)):
                return key, value
        return None, None

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        entry = make_entry(line_number, line)
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            entry["level"] = detect_level(line)
            return entry
        entry["_matched"] = True
        is_journal = "__REALTIME_TIMESTAMP" in obj
        used = set()

        key, value = self._pick(obj, self._TS_KEYS)
        if key:
            used.add(key)
            set_timestamp(entry, *_json_timestamp(key, value))

        key, value = self._pick(obj, self._MESSAGE_KEYS)
        if key:
            used.add(key)
            if isinstance(value, list):          # journald stores binary messages as byte arrays
                value = bytes(v for v in value if isinstance(
                    v, int) and 0 <= v < 256).decode("utf-8", "replace")
            entry["message"] = str(value)

        for target, keys in (("hostname", self._HOST_KEYS), ("process", self._PROCESS_KEYS)):
            key, value = self._pick(obj, keys)
            if key:
                used.add(key)
                entry[target] = str(value)

        key, value = self._pick(obj, self._PID_KEYS)
        if key and _to_int(value) is not None:
            used.add(key)
            entry["pid"] = _to_int(value)

        key, value = self._pick(obj, self._LEVEL_KEYS)
        if key:
            used.add(key)
            entry["level"] = normalize_level(value)

        if is_journal:
            if obj.get("_SYSTEMD_UNIT"):
                entry["fields"]["unit"] = obj["_SYSTEMD_UNIT"]
            facility = _to_int(obj.get("SYSLOG_FACILITY"))
            if facility is not None and facility < len(SYSLOG_FACILITY):
                entry["fields"]["facility"] = SYSLOG_FACILITY[facility]
        else:
            entry["fields"] = {k: v for k, v in obj.items() if k not in used}

        enrich_auth(entry)
        if entry["level"] is None:
            entry["level"] = detect_level(entry["message"])
        return entry


# ══════════════════════════════════════════════════════════════════════════════
#  GENERIC FALLBACK PARSER
# ══════════════════════════════════════════════════════════════════════════════
#
#  Handles most application logs: an ISO or syslog-style timestamp (optionally
#  in brackets) followed by text, with an explicit uppercase level token
#  like ERROR, [WARN], or "- INFO -" anywhere near the start.

_GENERIC_ISO_RE = re.compile(
    r"^\[?(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\]?\s*(?P<msg>.*)$",
    re.IGNORECASE,
)
_GENERIC_BSD_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<msg>.*)$")
_EXPLICIT_LEVEL_RE = re.compile(
    r"(?:^|[\s\[(|<:-])(?P<level>TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|SEVERE|"
    r"CRITICAL|CRIT|FATAL|ALERT|EMERG|EMERGENCY)(?=[\s\])|>:,-]|$)"
)


class GenericLogParser(BaseParser):
    name = "generic"
    log_type = "generic"
    description = "Fallback for anything else (timestamps + level keywords)"

    def parse_line(self, line_number: int, line: str) -> Optional[LogEntry]:
        entry = make_entry(line_number, line)
        body = line

        m = _GENERIC_ISO_RE.match(line)
        if m:
            dt = parse_iso_timestamp(m.group("ts"))
            if dt is not None:
                set_timestamp(entry, m.group("ts"), dt)
                body = m.group("msg").lstrip(" -|:")
        else:
            m = _GENERIC_BSD_RE.match(line)
            if m and _month(m.group("ts")) is not None:
                set_timestamp(entry, m.group("ts"),
                              self.resolver.bsd(m.group("ts")))
                body = m.group("msg")

        entry["message"] = body
        explicit = _EXPLICIT_LEVEL_RE.search(body[:80])
        entry["level"] = normalize_level(explicit.group(
            "level")) if explicit else detect_level(body)
        entry["_matched"] = entry["timestamp"] is not None or explicit is not None
        return entry


# ══════════════════════════════════════════════════════════════════════════════
#  FORMAT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# Order matters: when scores are close, earlier (more specific) parsers win.
PARSERS: Tuple[Type[BaseParser], ...] = (
    JsonLogParser, DpkgLogParser, AptLogParser, NginxLogParser, ApacheLogParser,
    AuthLogParser, KernelLogParser, SyslogParser, GenericLogParser,
)
PARSERS_BY_NAME: Dict[str, Type[BaseParser]] = {
    cls.name: cls for cls in PARSERS}
SNIFF_LINES = 100


def detect_parser_class(file_path: str, sample: Sequence[str]) -> Type[BaseParser]:
    """
    Choose a parser by content first, using the filename as a tiebreaker.
    Each parser scores how many sample lines it recognises. A filename-hinted
    parser wins if it recognises at least half as many lines as the best;
    otherwise the first parser within 80% of the best score wins.
    """
    lines = [line for line in sample if line.strip()]
    scores = {cls: sum(1 for line in lines if cls.sniff(line))
              for cls in PARSERS}
    best = max(scores.values(), default=0)

    hint_scores = {cls: cls.hint_score(file_path)
                   for cls in PARSERS} if file_path else {}
    top_hint = max(hint_scores.values(), default=0)
    hinted = next(
        (cls for cls in PARSERS if top_hint and hint_scores[cls] == top_hint), None)

    if best == 0:
        return hinted or GenericLogParser
    if hinted is not None and scores[hinted] >= 0.5 * best:
        return hinted
    return next(cls for cls in PARSERS if scores[cls] >= 0.8 * best)


def detect_parser(file_path: str, sample: Optional[Sequence[str]] = None) -> BaseParser:
    """Backwards-compatible helper: return a parser instance for `file_path`."""
    return detect_parser_class(file_path, sample or [])()


# ══════════════════════════════════════════════════════════════════════════════
#  FILE INPUT  (plain, .gz, .bz2, .xz, stdin)
# ══════════════════════════════════════════════════════════════════════════════

def open_log(file_path: str) -> IO[str]:
    """Open a log for reading, transparently decompressing by magic bytes."""
    if file_path == "-":
        buffer = getattr(sys.stdin, "buffer", None)
        return io.TextIOWrapper(buffer, encoding="utf-8", errors="replace") if buffer else sys.stdin

    with open(file_path, "rb") as probe:
        magic = probe.read(6)
    if magic.startswith(b"\x1f\x8b"):
        import gzip
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    if magic[:3] == b"BZh" and magic[3:4].isdigit():
        import bz2
        return bz2.open(file_path, "rt", encoding="utf-8", errors="replace")
    if magic.startswith(b"\xfd7zXZ\x00"):
        import lzma
        return lzma.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def read_errors() -> Tuple[Type[BaseException], ...]:
    """Exceptions that can surface while reading (incl. corrupt archives)."""
    errors: List[Type[BaseException]] = [OSError, EOFError]
    for module_name, attr in (("lzma", "LZMAError"), ("zlib", "error")):
        try:
            errors.append(getattr(__import__(module_name), attr))
        except ImportError:
            pass
    return tuple(errors)


def open_parser(file_path: str, log_type: str = "auto",
                year: Optional[int] = None) -> Tuple[IO[str], BaseParser, Iterator[str]]:
    """
    Open `file_path`, sample its first lines, and choose a parser.
    Returns (stream, parser, lines). The sampled lines are re-attached to the
    front of `lines`, so this works for stdin and compressed input too.
    """
    stream = open_log(file_path)
    try:
        sample_raw: List[str] = []
        iterator = iter(stream)
        non_blank = 0
        for line in iterator:
            sample_raw.append(line)
            if line.strip():
                non_blank += 1
                if non_blank >= SNIFF_LINES:
                    break
        sample = [line.rstrip("\r\n") for line in sample_raw]

        if log_type and log_type != "auto":
            cls = PARSERS_BY_NAME[log_type]
        else:
            cls = detect_parser_class(
                "" if file_path == "-" else file_path, sample)

        reference = None
        if file_path != "-":
            try:
                reference = datetime.fromtimestamp(os.path.getmtime(file_path))
            except (OSError, OverflowError, ValueError):
                reference = None

        parser = cls(TimestampResolver(reference, year))
        parser.prepare(sample)
    except BaseException:
        stream.close()
        raise
    return stream, parser, itertools.chain(sample_raw, iterator)


# ══════════════════════════════════════════════════════════════════════════════
#  FILTERING
# ══════════════════════════════════════════════════════════════════════════════

class EntryFilter:
    """An entry is kept only if it passes every configured condition."""

    def __init__(self, min_level: Optional[str] = None, since: Optional[datetime] = None,
                 until: Optional[datetime] = None, include: Optional["re.Pattern[str]"] = None,
                 exclude: Optional["re.Pattern[str]"] = None, processes: Optional[Iterable[str]] = None,
                 matched_only: bool = False):
        self.min_rank = LEVEL_RANK[min_level] if min_level else None
        self.since = to_aware(since) if since else None
        self.until = to_aware(until) if until else None
        self.include = include
        self.exclude = exclude
        self.processes = {p.lower() for p in processes} if processes else None
        self.matched_only = matched_only

    def __call__(self, entry: LogEntry) -> bool:
        if self.matched_only and not entry.get("_matched"):
            return False
        if self.min_rank is not None:
            # Entries without a level (or with a non-standard one) count as INFO.
            rank = LEVEL_RANK.get(
                entry.get("level") or "INFO", LEVEL_RANK["INFO"])
            if rank < self.min_rank:
                return False
        if self.processes is not None and (entry.get("process") or "").lower() not in self.processes:
            return False
        if self.since or self.until:
            dt = entry_datetime(entry)
            if dt is None:
                return False
            if (self.since and dt < self.since) or (self.until and dt > self.until):
                return False
        raw = entry.get("raw") or ""
        if self.include is not None and not self.include.search(raw):
            return False
        if self.exclude is not None and self.exclude.search(raw):
            return False
        return True


def select_entries(entries: Iterator[LogEntry], entry_filter: Optional[Callable[[LogEntry], bool]] = None,
                   tail: Optional[int] = None) -> Iterator[LogEntry]:
    if entry_filter is not None:
        entries = (e for e in entries if entry_filter(e))
    if tail:
        entries = iter(deque(entries, maxlen=tail))
    return entries


_RELATIVE_TIME_RE = re.compile(
    r"^(\d+)\s*(s|sec|secs|m|min|mins|h|hr|hrs|d|day|days|w|week|weeks)$", re.IGNORECASE)
_TIME_UNITS = {"s": "seconds", "m": "minutes",
               "h": "hours", "d": "days", "w": "weeks"}


def parse_time_argument(value: str) -> datetime:
    """Parse --since / --until: ISO dates/times, relative (2h, 3d), today, yesterday, now."""
    text = value.strip()
    now = datetime.now().astimezone()
    lower = text.lower()
    if lower == "now":
        return now
    if lower in ("today", "yesterday"):
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight - timedelta(days=1) if lower == "yesterday" else midnight
    rel = _RELATIVE_TIME_RE.match(text)
    if rel:
        return now - timedelta(**{_TIME_UNITS[rel.group(2)[0].lower()]: int(rel.group(1))})
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += " 00:00:00"
    dt = parse_iso_timestamp(text)
    if dt is None:
        raise argparse.ArgumentTypeError(
            f"invalid time '{value}' (examples: 2024-01-31, '2024-01-31 14:00', 2h, 3d, today)")
    return to_aware(dt)


# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY STATISTICS
# ══════════════════════════════════════════════════════════════════════════════

def _format_counter(counter: Counter, top: int) -> str:
    return ", ".join(f"{name} ({count:,})" for name, count in counter.most_common(top))


def _human_bytes(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{size:,.1f} TB"


class Summary:
    """Accumulates statistics over the entries that were written."""

    def __init__(self) -> None:
        self.entries = 0
        self.lines_read = 0
        self.unparsed_lines = 0
        self.levels: Counter = Counter()
        self.processes: Counter = Counter()
        self.hosts: Counter = Counter()
        self._first: Optional[Tuple[datetime, str]] = None
        self._last: Optional[Tuple[datetime, str]] = None
        self.http_status: Counter = Counter()
        self.http_clients: Counter = Counter()
        self.http_paths: Counter = Counter()
        self.http_bytes = 0
        self.auth_events: Counter = Counter()
        self.failed_logins_by_ip: Counter = Counter()
        self.failed_logins_by_user: Counter = Counter()
        self.logins_by_user: Counter = Counter()
        self.sudo_by_user: Counter = Counter()
        self.package_actions: Counter = Counter()

    def record_parser(self, parser: BaseParser) -> None:
        self.lines_read += parser.lines_read
        self.unparsed_lines += parser.unparsed_lines

    def add(self, entry: LogEntry) -> None:
        self.entries += 1
        self.levels[entry.get("level") or "(none)"] += 1
        fields = entry.get("fields") or {}
        if entry.get("process"):
            self.processes[entry["process"]] += 1
        if entry.get("hostname") and fields.get("kind") != "access":
            self.hosts[entry["hostname"]] += 1

        aware, iso = entry_datetime(entry), entry.get("timestamp_iso")
        if aware is not None:
            if self._first is None or aware < self._first[0]:
                self._first = (aware, iso)
            if self._last is None or aware > self._last[0]:
                self._last = (aware, iso)

        kind = fields.get("kind")
        if kind == "access":
            self.http_status[fields["status"]] += 1
            self.http_clients[fields.get("client_ip", "?")] += 1
            if fields.get("path"):
                self.http_paths[fields["path"].split("?", 1)[0]] += 1
            self.http_bytes += fields.get("bytes") or 0
        elif kind == "transaction":
            for action, packages in (fields.get("packages") or {}).items():
                self.package_actions[action] += len(packages)
        elif fields.get("action") in ("install", "upgrade", "remove", "purge"):
            self.package_actions[fields["action"]] += 1

        event = fields.get("event")
        if event:
            self.auth_events[event] += 1
            user = fields.get("user")
            if event == "login_failed":
                if fields.get("source_ip"):
                    self.failed_logins_by_ip[fields["source_ip"]] += 1
                if user:
                    self.failed_logins_by_user[user] += 1
            elif event == "login_success" and user:
                self.logins_by_user[user] += 1
            elif event == "sudo_command" and user:
                self.sudo_by_user[user] += 1

    def _sorted_levels(self) -> List[Tuple[str, int]]:
        return sorted(self.levels.items(), key=lambda kv: -LEVEL_RANK.get(kv[0], -1))

    def to_dict(self, top: int = 10) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "entries": self.entries,
            "lines_read": self.lines_read,
            "unparsed_lines": self.unparsed_lines,
        }
        if self._first and self._last:
            out["time_range"] = {
                "first": self._first[1], "last": self._last[1]}
        if self.levels:
            out["levels"] = dict(self._sorted_levels())
        if self.processes:
            out["top_processes"] = dict(self.processes.most_common(top))
        if self.hosts:
            out["top_hosts"] = dict(self.hosts.most_common(top))
        if self.http_status:
            out["http"] = {
                "status_codes": {str(code): n for code, n in sorted(self.http_status.items())},
                "top_clients": dict(self.http_clients.most_common(top)),
                "top_paths": dict(self.http_paths.most_common(top)),
                "total_bytes": self.http_bytes,
            }
        if self.auth_events:
            auth: Dict[str, Any] = {"events": dict(
                self.auth_events.most_common())}
            for key, counter in (("failed_logins_by_ip", self.failed_logins_by_ip),
                                 ("failed_logins_by_user",
                                  self.failed_logins_by_user),
                                 ("successful_logins_by_user", self.logins_by_user),
                                 ("sudo_commands_by_user", self.sudo_by_user)):
                if counter:
                    auth[key] = dict(counter.most_common(top))
            out["auth"] = auth
        if self.package_actions:
            out["packages"] = dict(self.package_actions.most_common())
        return out

    def render(self, title: str, top: int = 5) -> str:
        """Human-readable report for the terminal."""
        lines = [f"── {title} ".ljust(70, "─")]

        def row(label: str, value: str) -> None:
            lines.append(f"  {label:<16}: {value}")

        row("Lines read", f"{self.lines_read:,}  ({
            self.unparsed_lines:,} unrecognised)")
        row("Entries written", f"{self.entries:,}")
        if self._first and self._last:
            row("Time range", f"{self._first[1]}  →  {self._last[1]}")
        if self.levels:
            row("Levels", ", ".join(
                f"{name} {n:,}" for name, n in self._sorted_levels()))
        if self.processes:
            row("Top processes", _format_counter(self.processes, top))
        if self.hosts:
            row("Top hosts", _format_counter(self.hosts, top))
        if self.http_status:
            classes: Counter = Counter()
            for code, n in self.http_status.items():
                classes[f"{str(code)[0]}xx"] += n
            row("HTTP status", ", ".join(
                f"{c} {n:,}" for c, n in sorted(classes.items())))
            row("Top clients", _format_counter(self.http_clients, top))
            if self.http_paths:
                row("Top paths", _format_counter(self.http_paths, top))
            row("Bytes sent", _human_bytes(self.http_bytes))
        if self.auth_events:
            row("Auth events", _format_counter(self.auth_events, top))
            if self.failed_logins_by_ip:
                total = sum(self.failed_logins_by_ip.values())
                row("Failed SSH", f"{total:,} attempts from {
                    len(self.failed_logins_by_ip):,} source(s)")
                row("  by source", _format_counter(
                    self.failed_logins_by_ip, top))
            if self.failed_logins_by_user:
                row("  by user", _format_counter(
                    self.failed_logins_by_user, top))
            if self.logins_by_user:
                row("Logins by user", _format_counter(self.logins_by_user, top))
            if self.sudo_by_user:
                row("sudo by user", _format_counter(self.sudo_by_user, top))
        if self.package_actions:
            row("Packages", ", ".join(
                f"{a} {n:,}" for a, n in self.package_actions.most_common()))
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT WRITERS  (streaming: entries are written as they're parsed)
# ══════════════════════════════════════════════════════════════════════════════

class OutputWriter:
    extension = "txt"

    def __init__(self, out: IO[str], multi: bool = False):
        self.out = out
        self.multi = multi

    def start(self, parsed_at: str) -> None: ...
    def start_file(self, file_path: str, log_type: str) -> None: ...
    def write_entry(self, entry: LogEntry) -> None: ...
    def end_file(self, total_lines: int, summary: Dict[str, Any]) -> None: ...
    def finish(self, summary: Dict[str, Any]) -> None: ...


# C-accelerated, non-ASCII kept as-is
_encode_str = json.encoder.encode_basestring


def _json_scalar(value: Any) -> str:
    if isinstance(value, str):
        return _encode_str(value)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return int.__repr__(value)
    return json.dumps(value)


def pretty_json(value: Any, level: int = 0) -> str:
    """
    Same output as json.dumps(value, indent=2, ensure_ascii=False) but several
    times faster: with `indent`, the stdlib silently falls back to its
    pure-Python encoder, which dominated runtime on large logs.
    """
    if isinstance(value, dict):
        if not value:
            return "{}"
        pad = " " * (level + 2)
        body = ",\n".join(f"{pad}{_encode_str(str(k))}: {
                          pretty_json(v, level + 2)}" for k, v in value.items())
        return "{\n" + body + "\n" + " " * level + "}"
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        pad = " " * (level + 2)
        body = ",\n".join(pad + pretty_json(v, level + 2) for v in value)
        return "[\n" + body + "\n" + " " * level + "]"
    return _json_scalar(value)


class JsonWriter(OutputWriter):
    """
    Pretty-printed JSON, streamed. Single file: the v1 layout plus a "summary".
    Several files: {"parsed_at", "files": [...], "summary": <combined>}.
    """
    extension = "json"

    def __init__(self, out: IO[str], multi: bool = False):
        super().__init__(out, multi)
        self._key_indent = 6 if multi else 2
        self._files = 0
        self._entries = 0
        self._parsed_at = ""

    @staticmethod
    def _dump(value: Any, indent: int) -> str:
        return pretty_json(value, indent)

    def _field(self, key: str, value: Any, indent: int, last: bool = False) -> None:
        self.out.write(f"{' ' * indent}{json.dumps(key)
                                        }: {self._dump(value, indent)}{'' if last else ','}\n")

    def start(self, parsed_at: str) -> None:
        self._parsed_at = parsed_at
        self.out.write("{\n")
        if self.multi:
            self._field("parsed_at", parsed_at, 2)
            self.out.write('  "files": [')

    def start_file(self, file_path: str, log_type: str) -> None:
        indent = self._key_indent
        if self.multi:
            self.out.write(("," if self._files else "") + "\n    {\n")
        self._field("file_path", file_path, indent)
        self._field("log_type", log_type, indent)
        if not self.multi:
            self._field("parsed_at", self._parsed_at, indent)
        self.out.write(f'{" " * indent}"entries": [')
        self._entries = 0

    def write_entry(self, entry: LogEntry) -> None:
        indent = self._key_indent + 2
        self.out.write(("," if self._entries else "") + "\n" +
                       " " * indent + self._dump(entry, indent))
        self._entries += 1

    def end_file(self, total_lines: int, summary: Dict[str, Any]) -> None:
        indent = self._key_indent
        self.out.write(("\n" + " " * indent if self._entries else "") + "],\n")
        self._field("total_lines", total_lines, indent)
        self._field("summary", summary, indent, last=True)
        if self.multi:
            self.out.write("    }")
        self._files += 1

    def finish(self, summary: Dict[str, Any]) -> None:
        if self.multi:
            self.out.write("\n  ],\n")
            self._field("summary", summary, 2, last=True)
        self.out.write("}\n")


class JsonlWriter(OutputWriter):
    """One compact JSON object per line — ideal for jq, grep, and log shippers."""
    extension = "jsonl"
    _file_path = ""

    def start_file(self, file_path: str, log_type: str) -> None:
        self._file_path = file_path

    def write_entry(self, entry: LogEntry) -> None:
        if self.multi:
            entry = {"file_path": self._file_path, **entry}
        self.out.write(json.dumps(entry, ensure_ascii=False) + "\n")


class CsvWriter(OutputWriter):
    """Spreadsheet-friendly; `fields` is stored as a JSON string."""
    extension = "csv"
    COLUMNS = ("line_number", "timestamp", "timestamp_iso", "level", "hostname",
               "process", "pid", "message", "fields", "raw")
    _file_path = ""

    def start(self, parsed_at: str) -> None:
        self._csv = csv.writer(self.out)
        self._csv.writerow(
            (("file_path",) if self.multi else ()) + self.COLUMNS)

    def start_file(self, file_path: str, log_type: str) -> None:
        self._file_path = file_path

    def write_entry(self, entry: LogEntry) -> None:
        row = []
        for column in self.COLUMNS:
            value = entry.get(column)
            if column == "fields":
                value = json.dumps(value, ensure_ascii=False) if value else ""
            row.append("" if value is None else value)
        self._csv.writerow(([self._file_path] if self.multi else []) + row)


WRITERS: Dict[str, Type[OutputWriter]] = {
    "json": JsonWriter, "jsonl": JsonlWriter, "csv": CsvWriter}


class _Tee:
    def __init__(self, *streams: IO[str]):
        self.streams = streams

    def write(self, text: str) -> None:
        for stream in self.streams:
            stream.write(text)


class OutputTarget:
    """
    Writes to a temp file that replaces the destination only on success,
    so an interrupted run never leaves a half-written output file behind.
    """

    def __init__(self, path: str, echo: bool = False):
        self.path = path
        self._fh: Optional[IO[str]] = None
        self._tmp: Optional[str] = None
        if path == "-":
            self.stream: Any = sys.stdout
            return
        fd, self._tmp = tempfile.mkstemp(prefix=".logparser-", suffix=".tmp",
                                         dir=os.path.dirname(path) or ".")
        self._fh = os.fdopen(fd, "w", encoding="utf-8", newline="")
        self.stream = _Tee(self._fh, sys.stdout) if echo else self._fh

    def commit(self) -> None:
        if self._fh is not None and self._tmp is not None:
            self._fh.close()
            os.replace(self._tmp, self.path)
            self._fh = None
        else:
            sys.stdout.flush()

    def abort(self) -> None:
        if self._fh is not None and self._tmp is not None:
            self._fh.close()
            try:
                os.unlink(self._tmp)
            except OSError:
                pass
            self._fh = None


# ══════════════════════════════════════════════════════════════════════════════
#  LIBRARY API
# ══════════════════════════════════════════════════════════════════════════════

def display_path(file_path: str) -> str:
    return "<stdin>" if file_path == "-" else os.path.abspath(file_path)


def parse_file(file_path: str, log_type: str = "auto", year: Optional[int] = None,
               entry_filter: Optional[Callable[[LogEntry], bool]] = None,
               tail: Optional[int] = None, top: int = 10) -> ParseResult:
    """
    Parse a log into an in-memory result dict (same shape as the JSON output).
    For very large logs, prefer open_parser() + iter_entries(), which stream.

        >>> result = parse_file("/var/log/auth.log", entry_filter=EntryFilter(min_level="WARNING"))
    """
    stream, parser, lines = open_parser(file_path, log_type, year)
    summary = Summary()
    entries = []
    with stream:
        for entry in select_entries(parser.iter_entries(lines), entry_filter, tail):
            summary.add(entry)
            entries.append(clean_entry(entry))
    summary.record_parser(parser)
    return {
        "file_path":   display_path(file_path),
        "log_type":    parser.log_type,
        "parsed_at":   utc_now_iso(),
        "entries":     entries,
        "total_lines": parser.lines_read,
        "summary":     summary.to_dict(top),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT / OUTPUT VALIDATION & PROMPTS
# ══════════════════════════════════════════════════════════════════════════════

def validate_input_file(path: str) -> str:
    """Resolve and validate an input file path. Returns the absolute path."""
    abs_path = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"File not found: {abs_path}")
    if not os.path.isfile(abs_path):
        raise ValueError(f"Path is a directory, not a file: {abs_path}")
    if not os.access(abs_path, os.R_OK):
        raise PermissionError(f"No read permission for: {
                              abs_path} (try sudo?)")
    return abs_path


def validate_output_file(path: str) -> str:
    """Resolve and validate an output file path. Returns the absolute path."""
    abs_path = os.path.abspath(os.path.expanduser(path))
    parent_dir = os.path.dirname(abs_path)
    if not os.path.isdir(parent_dir):
        raise FileNotFoundError(
            f"Output directory does not exist: {parent_dir}")
    if os.path.isdir(abs_path):
        raise ValueError(f"Output path is a directory: {abs_path}")
    if not os.access(parent_dir, os.W_OK):
        raise PermissionError(
            f"No write permission for directory: {parent_dir}")
    return abs_path


def expand_inputs(paths: Sequence[str]) -> List[str]:
    """Validate inputs, expanding wildcards the shell didn't (e.g. when quoted)."""
    result: List[str] = []
    for path in paths:
        if path == "-":
            candidates = ["-"]
        elif any(ch in path for ch in "*?[") and not os.path.exists(path):
            matches = sorted(glob.glob(os.path.expanduser(path)))
            if not matches:
                raise FileNotFoundError(f"No files match: {path}")
            candidates = [validate_input_file(m)
                          for m in matches if os.path.isfile(m)]
        else:
            candidates = [validate_input_file(path)]
        result.extend(c for c in candidates if c not in result)
    return result


def default_output_path(input_path: str, extension: str = "json") -> str:
    """auth.log.2.gz -> ./auth_parsed.json"""
    stem = "stdin" if input_path == "-" else os.path.basename(input_path)
    stem = re.sub(r"\.(gz|bz2|xz)$", "", stem, flags=re.IGNORECASE)
    stem = re.sub(r"\.\d+$", "", stem)
    stem = re.sub(r"\.(log|txt)$", "", stem, flags=re.IGNORECASE) or "output"
    return os.path.join(os.getcwd(), f"{stem}_parsed.{extension}")


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


def prompt_output_file(default: Optional[str] = None) -> str:
    """Interactively prompt for an output path; Enter accepts the default."""
    hint = f" [{default}]" if default else ""
    while True:
        try:
            path = input(f"Enter the path to save the output{
                         hint}: ").strip() or (default or "")
            if not path:
                print("  Please enter a file path.\n")
                continue
            return validate_output_file(path)
        except (FileNotFoundError, ValueError, PermissionError) as exc:
            print(f"  Error: {exc}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  HELP MENU
# ══════════════════════════════════════════════════════════════════════════════

def render_help() -> str:
    title = f"Linux Log Parser v{__version__}  —  Help Menu"
    rows = [("auto", "Detect from file contents (default)")] + \
        [(c.name, c.description) for c in PARSERS]
    table = ["  ┌──────────┬" + "─" * 60 + "┐",
             f"  │ {'Type':<8} │ {'Covers':<58} │",
             "  ├──────────┼" + "─" * 60 + "┤"]
    table += [f"  │ {name:<8} │ {desc:<58} │" for name, desc in rows]
    table.append("  └──────────┴" + "─" * 60 + "┘")

    return f"""
╔{'═' * 70}╗
║{title.center(70)}║
╚{'═' * 70}╝

DESCRIPTION
  Parses common Linux log files (plain or .gz/.bz2/.xz compressed) into
  structured JSON, JSON Lines, or CSV. The format is detected from the
  file's contents, timestamps are normalised to ISO 8601, and a summary
  report (levels, top processes, HTTP stats, failed logins, …) is shown
  when parsing finishes.

USAGE
  python logparser.py                          Interactive mode
  python logparser.py <file> [<file> ...]      Parse one or more files
  python logparser.py -i <input> -o <output>   Explicit input and output
  <command> | python logparser.py -o -         Read stdin, write stdout

INPUT
  -i, --input <path>...   Log file(s) to parse; positional paths also work.
                          "-" reads stdin. Wildcards such as 'auth.log*'
                          are expanded even when quoted.
  -t, --log-type <type>   Force a parser instead of auto-detecting.
      --year <yyyy>       Year for syslog timestamps that lack one
                          (default: inferred from the file's mtime).

OUTPUT
  -o, --output <path>     Where to save results; "-" writes to stdout.
                          Default: ./<input-name>_parsed.<format>
                          (stdout when reading from stdin).
  -f, --format <fmt>      json (default), jsonl, or csv.
      --print             Also echo the output to the terminal.
      --top <n>           Items in each "top" summary list (default 10).
  -q, --quiet             Hide the banner and summary report.

FILTERS  (combine freely — an entry must pass all of them)
  -l, --level <level>     Minimum severity: 'warning' keeps WARNING and
                          above. Entries with no level count as INFO.
      --since <time>      Keep entries at or after <time>.
      --until <time>      Keep entries at or before <time>.
                          <time>: 2024-01-31, '2024-01-31 14:00', 30m,
                          2h, 3d, 1w, today, yesterday. Entries without a
                          wall-clock timestamp are dropped by these.
  -g, --grep <regex>      Keep lines matching <regex>.
  -x, --exclude <regex>   Drop lines matching <regex>.
  -I, --ignore-case       Make --grep / --exclude case-insensitive.
  -p, --process <name>    Keep only these processes (repeatable, or
                          comma-separated: -p sshd,sudo).
      --matched-only      Drop lines the parser couldn't recognise.
  -n, --tail <n>          Keep only the last <n> matching entries per file.

OTHER
  -h, --help              Show this help menu and exit.
  -V, --version           Show the version and exit.
      --list-types        List supported log types and exit.

SUPPORTED LOG FORMATS  (content-detected; the filename breaks ties)
{chr(10).join(table)}

JSON OUTPUT FIELDS
  file_path      Absolute path of the parsed file ("<stdin>" for stdin)
  log_type       Detected log format
  parsed_at      UTC time the parse was performed
  entries[]      Parsed entries (empty keys are omitted):
    line_number    Line number in the original file
    timestamp      Timestamp exactly as written in the log
    timestamp_iso  Normalised ISO 8601 timestamp
    level          EMERGENCY/ALERT/CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG/TRACE
    hostname       Source hostname (client IP for web access logs)
    process        Process or service name
    pid            Process ID (integer)
    message        Parsed log message
    fields         Format-specific details: HTTP method/path/status,
                   SSH events (user, source_ip), sudo commands, dpkg and
                   APT package actions, journald unit, …
    raw            Original unmodified line(s)
  total_lines    Lines read from the file
  summary        Counts by level/process/host, time range, and HTTP,
                 authentication, and package statistics where relevant
  With several input files, each is listed under "files" and a combined
  "summary" is added at the top level.

EXAMPLES
  python logparser.py /var/log/syslog -o /tmp/syslog.json
  python logparser.py /var/log/auth.log* --level warning
  python logparser.py access.log --grep '" 5[0-9][0-9] ' -f csv -o 5xx.csv
  python logparser.py /var/log/syslog --since 2h -p sshd,sudo -f jsonl -o -
  journalctl -o json --since today | python logparser.py -o today.json
  dmesg -x | python logparser.py -t kern --level error
"""


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def _level_argument(value: str) -> str:
    level = normalize_level(value)
    if level not in LEVEL_RANK:
        raise argparse.ArgumentTypeError(
            f"unknown level '{value}' (choose from: {', '.join(l.lower() for l in LEVELS)})")
    return level  # type: ignore[return-value]


def _positive_int(value: str) -> int:
    number = _to_int(value)
    if number is None or number <= 0:
        raise argparse.ArgumentTypeError(
            f"expected a positive integer, got '{value}'")
    return number


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="logparser.py",
        description="Linux Log Parser — parses log files into JSON, JSON Lines, or CSV",
        add_help=False,   # we print our own help
    )
    ap.add_argument("files", nargs="*", metavar="FILE",
                    help="Input log file(s)")
    ap.add_argument("-i", "--input", nargs="+",
                    action="extend", default=[], metavar="<path>")
    ap.add_argument("-o", "--output", metavar="<path>")
    ap.add_argument("-f", "--format", choices=tuple(WRITERS), default="json")
    ap.add_argument("-t", "--log-type", choices=("auto",) +
                    tuple(PARSERS_BY_NAME), default="auto")
    ap.add_argument("--year", type=_positive_int)
    ap.add_argument("-l", "--level", type=_level_argument)
    ap.add_argument("--since", type=parse_time_argument)
    ap.add_argument("--until", type=parse_time_argument)
    ap.add_argument("-g", "--grep", metavar="<regex>")
    ap.add_argument("-x", "--exclude", metavar="<regex>")
    ap.add_argument("-I", "--ignore-case", action="store_true")
    ap.add_argument("-p", "--process", action="append", metavar="<name>")
    ap.add_argument("--matched-only", action="store_true")
    ap.add_argument("-n", "--tail", type=_positive_int)
    ap.add_argument("--top", type=_positive_int, default=10)
    ap.add_argument("--print", action="store_true", dest="print_output")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("-V", "--version", action="store_true")
    ap.add_argument("--list-types", action="store_true")
    return ap


def build_filter(args: argparse.Namespace) -> Optional[EntryFilter]:
    flags = re.IGNORECASE if args.ignore_case else 0
    try:
        include = re.compile(args.grep, flags) if args.grep else None
        exclude = re.compile(args.exclude, flags) if args.exclude else None
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}") from exc
    if args.since and args.until and args.since > args.until:
        raise ValueError("--since is later than --until")
    processes = [p.strip() for chunk in (args.process or [])
                 for p in chunk.split(",") if p.strip()]
    if not any((args.level, args.since, args.until, include, exclude, processes, args.matched_only)):
        return None
    return EntryFilter(min_level=args.level, since=args.since, until=args.until, include=include,
                       exclude=exclude, processes=processes, matched_only=args.matched_only)


def run(args: argparse.Namespace) -> int:
    def info(message: str = "") -> None:
        if not args.quiet:
            print(message, file=sys.stderr)

    # ── Resolve inputs ────────────────────────────────────────────────────────
    raw_inputs = list(args.files) + list(args.input)
    interactive = False
    if not raw_inputs:
        if sys.stdin.isatty():
            interactive = True
            info("=" * 44)
            info(f"        Linux Log Parser v{__version__}")
            info("=" * 44 + "\n")
            raw_inputs = [prompt_input_file()]
        else:
            raw_inputs = ["-"]

    try:
        inputs = expand_inputs(raw_inputs)
        entry_filter = build_filter(args)
    except (FileNotFoundError, ValueError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # ── Resolve output ────────────────────────────────────────────────────────
    writer_cls = WRITERS[args.format]
    try:
        if args.output:
            output_path = "-" if args.output == "-" else validate_output_file(
                args.output)
        elif interactive:
            output_path = prompt_output_file(
                default_output_path(inputs[0], writer_cls.extension))
        elif inputs == ["-"]:
            output_path = "-"
        else:
            output_path = default_output_path(inputs[0], writer_cls.extension)
            info(f"No output file specified — defaulting to: {output_path}")
    except (FileNotFoundError, ValueError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if output_path != "-" and output_path in inputs:
        print(f"Error: output would overwrite an input file: {
              output_path}", file=sys.stderr)
        return 1

    info(f"\nInput  : {', '.join(display_path(p) for p in inputs)}")
    info(f"Output : {'<stdout>' if output_path ==
         '-' else output_path}  ({args.format})\n")

    # ── Parse & write ─────────────────────────────────────────────────────────
    multi = len(inputs) > 1
    target = OutputTarget(output_path, echo=args.print_output)
    writer = writer_cls(target.stream, multi=multi)
    combined = Summary()
    current = ""
    try:
        writer.start(utc_now_iso())
        for path in inputs:
            current = display_path(path)
            stream, parser, lines = open_parser(path, args.log_type, args.year)
            summary = Summary() if multi else combined
            with stream:
                writer.start_file(current, parser.log_type)
                for entry in select_entries(parser.iter_entries(lines), entry_filter, args.tail):
                    summary.add(entry)
                    if multi:
                        combined.add(entry)
                    writer.write_entry(clean_entry(entry))
            summary.record_parser(parser)
            if multi:
                combined.record_parser(parser)
            writer.end_file(parser.lines_read, summary.to_dict(args.top))
            info(f"  ✓ {current}  [{parser.log_type}]  "
                 f"{parser.lines_read:,} lines → {summary.entries:,} entries")
        writer.finish(combined.to_dict(args.top))
        target.commit()
    except BrokenPipeError:
        target.abort()
        raise
    except read_errors() as exc:
        target.abort()
        print(f"\nError while processing {
              current or 'input'}: {exc}", file=sys.stderr)
        return 1
    except BaseException:
        target.abort()
        raise

    info()
    info(combined.render(
        "Summary" if not multi else f"Combined summary ({len(inputs)} files)", top=5))
    if output_path != "-":
        info(f"\n Done. Results saved to : {output_path}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_arg_parser()
    args = ap.parse_args(argv)

    if args.help:
        print(render_help())
        return 0
    if args.version:
        print(f"logparser.py {__version__}")
        return 0
    if args.list_types:
        print("auto       Detect from file contents (default)")
        for cls in PARSERS:
            print(f"{cls.name:<10} {cls.description}")
        return 0

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except EOFError:            # Ctrl-D at an interactive prompt
        print("\nCancelled.", file=sys.stderr)
        return 1
    except BrokenPipeError:     # e.g. piping into `head`
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
