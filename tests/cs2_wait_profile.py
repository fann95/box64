"""Bounded, filtered scheduler recording and offline off-CPU analysis for CS2.

The caller owns process discovery, output creation and the recorder timeout.
This module never attaches a debugger, signals the game or changes sysctls.
All timestamps in reports are CLOCK_MONOTONIC nanoseconds, not wall time.
"""
from __future__ import annotations

from decimal import Decimal
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def _tid(value):
    if isinstance(value, bool) or int(value) != value or int(value) <= 0:
        raise ValueError("TIDs must be positive integers")
    return int(value)


def _environment():
    return {**os.environ, "LC_ALL": "C", "DEBUGINFOD_URLS": ""}


def probe(privilege_prefix=("sudo", "-n")):
    """Read tracepoint formats; this does not open events or change the system."""
    result = {"ready": False, "errors": [], "event_open_validated": False,
              "clock": "CLOCK_MONOTONIC", "formats": ""}
    for base in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        paths = [f"{base}/events/sched/{name}/format"
                 for name in ("sched_switch", "sched_wakeup")]
        try:
            run = subprocess.run([*privilege_prefix, "cat", *paths], capture_output=True,
                                 text=True, timeout=3, env=_environment())
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["errors"].append(str(exc))
            return result
        if run.returncode == 0:
            result["formats"] = run.stdout
            result["paths"] = paths
            required = ("prev_pid", "next_pid", "prev_state", "sched_wakeup")
            result["ready"] = all(term in run.stdout for term in required)
            if not result["ready"]:
                result["errors"].append("Tracepoint formats do not contain the required fields")
            return result
        result["errors"].append(run.stderr.strip() or f"cat exited {run.returncode}")
        if "sudo:" in run.stderr:
            return result
    return result


def build_record_command(main_tid, audio_tid, output, duration=10.0,
                         privilege_prefix=("sudo", "-n")):
    """Record both switch directions without optional user-register sampling.

    Some ARM kernels reject tracepoints with DWARF user stacks. perf may then
    drop that event and still exit zero, leaving only switch-ins in the file.
    Keep both directions in one event; CPU/JIT attribution is recorded separately.
    """
    tids = sorted({_tid(main_tid), _tid(audio_tid)})
    duration = float(duration)
    if not math.isfinite(duration) or not 0.001 <= duration <= 10.0:
        raise ValueError("Scheduler capture duration must be between 0.001 and 10 seconds")
    duration_ms = int(duration * 1000)
    switch_filter = " || ".join(f"{field} == {tid}" for field in ("prev_pid", "next_pid") for tid in tids)
    wake_filter = " || ".join(f"pid == {tid}" for tid in tids)
    return [*privilege_prefix, "perf", "record", "-a", "--clockid", "mono",
            "--delay", f"0-{duration_ms}", "-T", "--sample-cpu",
            "-m", "512K", "--max-size", "64M", "--no-buildid", "--no-buildid-cache",
            "--no-buildid-mmap",
            "-e", "sched:sched_switch/call-graph=no/", "--filter", switch_filter,
            "-e", "sched:sched_wakeup/call-graph=no/", "--filter", wake_filter,
            "-o", str(Path(output)), "--", "sleep", str(duration)]


def recording_errors(returncode, log):
    errors = []
    if returncode:
        errors.append(f"Scheduler recorder exited {returncode}")
    if re.search(r"lost|max-size|maximum size|size limit|failure to open|will be removed|"
                 r"doesn't support|permission denied|^error:", log, re.I | re.M):
        errors.append("Scheduler recording was incomplete; see wait.log")
    return errors


def check_recording(privilege_prefix=("sudo", "-n")):
    """One-second test on our own sleeping child; never touch a game process."""
    result = probe(privilege_prefix)
    if not result["ready"]:
        return result
    result["errors"] = []
    result["ready"] = False
    result["user_stacks"] = False
    with tempfile.TemporaryDirectory(prefix="box64-sched-probe-") as directory:
        child = subprocess.Popen([sys.executable, "-c",
                                  "import time\nfor _ in range(1000): time.sleep(0.01)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            path = Path(directory) / "probe.data"
            # perf preserves an existing empty file's owner, but creates a new
            # file as root with mode 0600 when called through sudo.
            path.touch(mode=0o600)
            command = build_record_command(child.pid, child.pid, path, duration=1,
                                           privilege_prefix=())
            command = [*privilege_prefix, "timeout", "-s", "INT", "-k", "2s", "5s", *command]
            run = subprocess.run(command, capture_output=True, text=True, timeout=9, env=_environment())
            result["record_log"] = run.stdout + run.stderr
            result["errors"].extend(recording_errors(run.returncode, result["record_log"]))
            if not result["errors"]:
                decoded = report(path, child.pid, child.pid)
                stats = decoded.get("threads", {}).get(str(child.pid), {})
                result["thread"] = stats
                result["errors"].extend(decoded["errors"][:10])
                result["event_open_validated"] = bool(
                    decoded["reliable"] and stats.get("complete_interval_count", 0) >= 3
                    and stats.get("complete_sleep_ns", 0) > 0)
                if not result["event_open_validated"] and not result["errors"]:
                    result["errors"].append("Probe lacks complete sleep/wakeup/switch intervals")
        except (OSError, subprocess.TimeoutExpired) as error:
            result["errors"].append(str(error))
        finally:
            child.terminate()
            child.wait(timeout=3)
    result["ready"] = result["event_open_validated"] and not result["errors"]
    return result


def _ns(seconds):
    return int(Decimal(str(seconds)) * 1_000_000_000)


_HEADER = re.compile(r"\[(?P<cpu>\d+)\]\s+(?P<time>\d+\.\d+):\s+"
                     r"(?P<event>\S+):\s*(?P<body>.*)$")
_STACK = re.compile(r"^\s+(?:0x)?([0-9a-fA-F]{4,16})\s+")
_SWITCH = re.compile(r"prev_pid=(\d+).*?prev_state=(\S+).*?next_pid=(\d+)")
_WAKE = re.compile(r"(?:^|\s)pid=(\d+)(?:\s|$)")
# libtraceevent's scheduler plugin prints comm:pid instead of key=value fields.
# Match the priorities and arrow too; comm itself can contain spaces or colons.
_SWITCH_COMPACT = re.compile(r"^.*?:(\d+)\s+\[\d+\]\s+(\S+)\s+==>\s+.*?:(\d+)\s+\[\d+\]")
_WAKE_COMPACT = re.compile(r"^.*?:(\d+)\s+\[\d+\]\s+CPU:\d+\b")


def parse_script(text):
    """Parse perf script --ns trace output; retain raw text separately in report()."""
    events, errors, lost_records = [], [], []
    current = None
    for line in text.splitlines():
        if "PERF_RECORD_LOST" in line or re.search(r"\bLOST\s+\d+\s+events", line):
            lost_records.append(line.strip())
            current = None
            continue
        header = _HEADER.search(line)
        if header:
            current = None
            event_name, body = header["event"], header["body"]
            event = {"timestamp_ns": _ns(header["time"]), "cpu": int(header["cpu"]),
                     "stack_ips": []}
            if "sched_switch" in event_name:
                match = _SWITCH.search(body) or _SWITCH_COMPACT.search(body)
                if not match:
                    errors.append(f"Cannot parse switch record: {line}")
                    continue
                event.update(kind="switch", prev_tid=int(match[1]), prev_state=match[2],
                             next_tid=int(match[3]))
            elif "sched_wakeup" in event_name:
                match = _WAKE.search(body) or _WAKE_COMPACT.search(body)
                if not match:
                    errors.append(f"Cannot parse wakeup record: {line}")
                    continue
                event.update(kind="wakeup", tid=int(match[1]))
            else:
                continue
            events.append(event)
            current = event
        elif current and (stack := _STACK.match(line)):
            current["stack_ips"].append(int(stack[1], 16))
        elif line.strip() and ("sched_switch:" in line or "sched_wakeup:" in line):
            errors.append(f"Unrecognized scheduler record: {line}")
            current = None
    # Two filtered switch events both fire on a switch between selected threads.
    unique = {}
    for event in events:
        key = (event["kind"], event["timestamp_ns"], event["cpu"], event.get("prev_tid"),
               event.get("next_tid"), event.get("prev_state"), event.get("tid"))
        if key not in unique:
            unique[key] = event
        elif event["stack_ips"] and not unique[key]["stack_ips"]:
            unique[key]["stack_ips"] = event["stack_ips"]
    return {"events": sorted(unique.values(), key=lambda item: item["timestamp_ns"]),
            "errors": errors, "lost_records": lost_records}


def analyze_events(parsed, main_tid, audio_tid, *, window_start=None, window_end=None):
    """Split complete off-CPU intervals into blocked sleep and runnable delay.

    window_start/end are monotonic SECONDS (matching time.monotonic()). Output is
    integer nanoseconds. Censored intervals are excluded from complete totals.
    Without a wakeup, a complete non-running interval cannot be split reliably.
    """
    tids = sorted({_tid(main_tid), _tid(audio_tid)})
    events = parsed["events"]
    errors = list(parsed.get("errors", []))
    if not events:
        return {"reliable": False, "errors": errors + ["No scheduler events captured"],
                "lost_records": parsed.get("lost_records", []), "intervals": [], "threads": {}}
    start = _ns(window_start) if window_start is not None else events[0]["timestamp_ns"]
    end = _ns(window_end) if window_end is not None else events[-1]["timestamp_ns"]
    if end < start:
        raise ValueError("window_end precedes window_start")
    pending, seen, intervals = {}, set(), []

    def close(tid, until, right=False, reason=None):
        wait = pending.pop(tid)
        beginning = wait["start_ns"]
        duration = max(0, until - beginning)
        state, wake = wait["prev_state"], wait.get("wakeup_ns")
        sleep, runnable, unknown = None, None, duration
        flags = list(wait.get("flags", []))
        if reason:
            flags.append(reason)
        if state in ("R", "R+"):
            sleep, runnable, unknown = 0, duration, 0
        elif wake is not None and beginning <= wake <= until:
            runnable = until - wake
            if state in ("S", "D", "I"):
                sleep, unknown = wake - beginning, 0
            else:
                unknown = wake - beginning
        elif state in ("S", "D", "I") and right:
            # No wakeup before the end: only a censored lower bound on sleep.
            sleep, runnable, unknown = duration, 0, 0
        elif not wait["censored_left"] and not right:
            flags.append("missing_wakeup" if state in ("S", "D", "I") else "unknown_state")
            errors.append(f"TID {tid}: cannot split interval {beginning}..{until} ({state})")
        intervals.append({**wait, "tid": tid, "end_ns": until, "duration_ns": duration,
                          "sleep_ns": sleep, "runnable_ns": runnable, "unattributed_ns": unknown,
                          "censored_right": right, "censored": wait["censored_left"] or right,
                          "flags": flags})

    for event in events:
        when = event["timestamp_ns"]
        if not start <= when <= end:
            continue
        if event["kind"] == "wakeup":
            tid = event["tid"]
            if tid not in tids:
                continue
            if tid not in pending and tid not in seen:
                pending[tid] = {"start_ns": start, "prev_state": None, "censored_left": True,
                                "stack_ips": [], "stack_timestamp_ns": None, "flags": []}
            if tid in pending:
                pending[tid].setdefault("wakeup_ns", when)
            continue
        incoming, outgoing = event["next_tid"], event["prev_tid"]
        if incoming in tids:
            if incoming in pending:
                close(incoming, when)
            elif incoming not in seen:
                pending[incoming] = {"start_ns": start, "prev_state": None,
                                     "censored_left": True, "stack_ips": [],
                                     "stack_timestamp_ns": None, "flags": []}
                close(incoming, when)
            else:
                errors.append(f"TID {incoming}: switch-in without a recorded switch-out at {when}")
            seen.add(incoming)
        if outgoing in tids:
            if outgoing in pending:
                close(outgoing, when, right=True, reason="missing_switch_in")
                errors.append(f"TID {outgoing}: repeated switch-out at {when}")
            pending[outgoing] = {"start_ns": when, "prev_state": event["prev_state"],
                                 "censored_left": False, "stack_ips": event["stack_ips"],
                                 "stack_timestamp_ns": when, "flags": []}
            seen.add(outgoing)
    for tid in list(pending):
        close(tid, end, right=True)
    intervals.sort(key=lambda item: (item["start_ns"], item["tid"]))
    summaries = {}
    for tid in tids:
        selected = [item for item in intervals if item["tid"] == tid]
        complete = [item for item in selected if not item["censored"]]
        summaries[str(tid)] = {
            "interval_count": len(selected), "complete_interval_count": len(complete),
            "censored_interval_count": len(selected) - len(complete),
            "complete_offcpu_ns": sum(item["duration_ns"] for item in complete),
            "complete_sleep_ns": sum(item["sleep_ns"] or 0 for item in complete),
            "complete_runnable_ns": sum(item["runnable_ns"] or 0 for item in complete),
            "complete_unattributed_ns": sum(item["unattributed_ns"] for item in complete),
            "censored_offcpu_ns": sum(item["duration_ns"] for item in selected if item["censored"]),
        }
    lost = parsed.get("lost_records", [])
    return {"clock": "CLOCK_MONOTONIC", "window_start_ns": start, "window_end_ns": end,
            "window_inferred_from_events": window_start is None or window_end is None,
            "reliable": not errors and not lost, "errors": errors, "lost_records": lost,
            "intervals": intervals, "threads": summaries}


def report(data_path, main_tid, audio_tid, *, window_start=None, window_end=None):
    """Read a completed perf file; return raw PCs/text as well as the interval report."""
    command = ["perf", "script", "--ns", "--show-lost-events", "--max-stack", "32",
               "-F", "trace:comm,pid,tid,cpu,time,event,trace,ip,sym,dso", "-i", str(data_path)]
    try:
        run = subprocess.run(command, capture_output=True, text=True, timeout=30,
                             env=_environment())
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"reliable": False, "errors": [str(exc)], "intervals": [], "threads": {},
                "raw_script": "", "script_stderr": "", "script_command": command}
    parsed = parse_script(run.stdout)
    if run.returncode:
        parsed["errors"].append(f"perf script failed ({run.returncode}): {run.stderr.strip()}")
    # Perf can report truncated input/lost events on stderr even with partial stdout.
    if re.search(r"lost|truncat|failed|error", run.stderr, re.I):
        parsed["errors"].append(run.stderr.strip())
    result = analyze_events(parsed, main_tid, audio_tid,
                            window_start=window_start, window_end=window_end)
    result.update(raw_script=run.stdout, script_stderr=run.stderr, script_command=command)
    return result
