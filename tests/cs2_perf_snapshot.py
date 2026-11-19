#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two short, passive CS2 profiles; no affinity or game configuration changes."""

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def proc_stat(path):
    text = (path / "stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    return {"starttime": int(fields[19]), "state": fields[0],
            "utime": int(fields[11]), "stime": int(fields[12]),
            "last_cpu": int(fields[36])}


def identity(pid):
    path = Path(f"/proc/{pid}")
    return (path.stat().st_uid, proc_stat(path)["starttime"],
            os.readlink(path / "exe"))


def is_cs2(pid):
    try:
        path = Path(f"/proc/{pid}")
        if not Path(os.readlink(path / "exe")).name.startswith("box64"):
            return False
        args = (path / "cmdline").read_bytes().split(b"\0")
        return any(arg.endswith(b"/linuxsteamrt64/cs2") or arg == b"cs2"
                   for arg in args)
    except OSError:
        return False


def find_game(explicit=None):
    candidates = [explicit] if explicit else [int(p.name) for p in Path("/proc").glob("[0-9]*")]
    matches = []
    for pid in candidates:
        try:
            if is_cs2(pid) and identity(pid)[0] == os.getuid():
                matches.append(pid)
        except OSError:
            pass
    if len(matches) != 1:
        raise RuntimeError(f"Нужен один запущенный процесс CS2 своего пользователя; найдено: {matches}.")
    return matches[0]


def checked_identity(pid, expected):
    if identity(pid) != expected:
        raise RuntimeError("CS2 завершилась или процесс сменился. Этот замер непригоден для сравнения.")


def status_fields(path):
    wanted = {"VmRSS", "VmSize", "RssAnon", "RssFile", "VmSwap", "Threads",
              "Cpus_allowed_list", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}
    return {key: value.strip() for line in (path / "status").read_text().splitlines()
            for key, _, value in [line.partition(":")] if key in wanted}


def snapshot(pid, expected):
    checked_identity(pid, expected)
    root = Path(f"/proc/{pid}")
    result = {"monotonic": time.monotonic(), "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": status_fields(root), "threads": {}}
    for task in (root / "task").iterdir():
        try:
            data = proc_stat(task)
            data.update(status_fields(task))
            data["name"] = (task / "comm").read_text().strip()
            data["wchan"] = (task / "wchan").read_text().strip()
            data["schedstat"] = [int(v) for v in (task / "schedstat").read_text().split()]
            if proc_stat(task)["starttime"] == data["starttime"]:
                result["threads"][task.name] = data
        except (OSError, ValueError):  # Threads can exit during a snapshot.
            continue
    checked_identity(pid, expected)
    return result


def thread_summary(first, last):
    seconds = last["monotonic"] - first["monotonic"]
    hz = os.sysconf("SC_CLK_TCK")
    rows = []
    for tid, end in last["threads"].items():
        start = first["threads"].get(tid)
        if not start or start["starttime"] != end["starttime"]:
            continue
        cpu = 100 * ((end["utime"] + end["stime"]) - (start["utime"] + start["stime"])) / hz / seconds
        rows.append((cpu, tid, end))
    lines = ["CPU%: 100% = одно полностью занятое ядро. Только потоки, существовавшие в обоих снимках.",
             "last_cpu — последнее ядро, не распределение времени; распределение есть в perf ниже."]
    for cpu, tid, end in sorted(rows, reverse=True)[:25]:
        lines.append(f"{cpu:7.2f}% tid={tid} {end['name']} state={end['state']} "
                     f"wchan={end['wchan']} allowed={end['Cpus_allowed_list']} last_cpu={end['last_cpu']}")
    return "\n".join(lines)


def perf_report(data, pid, sort):
    result = subprocess.run(
        ["perf", "report", "--stdio", "--stdio-color", "never", "--no-children",
         "--percent-limit", "0.5", "--show-nr-samples", "--pid", str(pid),
         "--sort", sort, "-i", str(data)],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        raise RuntimeError(f"perf report: {result.stderr.strip()}; исходный профиль сохранён: {data}")
    return result.stdout + ("\n" + result.stderr if result.stderr else "")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("normal", "slow"), help="normal: FPS нормальный; slow: уже просел")
    parser.add_argument("--pid", type=int, help="PID CS2, если автоматический поиск неоднозначен")
    parser.add_argument("--seconds", type=int, default=10, choices=range(5, 21), metavar="5..20")
    args = parser.parse_args()
    if os.getuid() == 0:
        raise RuntimeError("Запускай python3 без sudo. Только perf запросит повышенные права.")
    for tool in ("perf", "sudo", "timeout"):
        if not shutil.which(tool):
            raise RuntimeError(f"Не найдена команда {tool}.")
    pid = find_game(args.pid)
    original = identity(pid)
    output = Path(__file__).resolve().parents[1] / "build" / "cs2-profile"
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    comparison_note = ""
    if args.phase == "slow" and (output / "normal.json").exists():
        previous = json.loads((output / "normal.json").read_text())
        if previous["pid"] != pid or previous["identity"] != list(original):
            comparison_note = ("Нормальный профиль относится к другому запуску CS2. "
                               "Сохраняю отдельный профиль тормозов; прежний normal остаётся ориентиром, "
                               "а не строгим сравнением одинаковых условий.")
            print(comparison_note, flush=True)
    subprocess.run(["sudo", "-v"], check=True)
    print(f"CS2 PID {pid}. Через 10 секунд начнётся запись на {args.seconds} секунд.", flush=True)
    print("Вернись в игру. Оставь её на переднем плане, без меню; играй обычным образом.", flush=True)
    print("Привязка ядер и настройки игры не меняются. Нажатие Ctrl+C отменяет замер.", flush=True)
    time.sleep(10)
    checked_identity(pid, original)
    maps_before = Path(f"/proc/{pid}/maps").read_text()
    samples = [snapshot(pid, original)]
    fd, name = tempfile.mkstemp(prefix=f".{args.phase}-", suffix=".data", dir=output)
    os.close(fd)  # Root perf writes a file owned by this user; no root-owned results.
    temporary = Path(name)
    log_path = output / f"{args.phase}.perf-log.txt"
    command = ["sudo", "-n", "timeout", "-s", "INT", "-k", "3s", f"{args.seconds + 5}s",
               "perf", "record", "-e", "cpu-clock:u", "-F", "99", "--sample-cpu", "-T",
               "--no-buildid", "--no-buildid-cache", "-p", str(pid), "-o", str(temporary),
               "--", "sleep", str(args.seconds)]
    print("ЗАПИСЬ", flush=True)
    try:
        with log_path.open("w") as log:
            proc = subprocess.Popen(command, stdout=log, stderr=log)
            try:
                while True:
                    try:
                        code = proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        samples.append(snapshot(pid, original))
                        continue
                    break
            finally:
                if proc.poll() is None:
                    # sudo forwards TERM to the timed recorder, never to CS2.
                    try:
                        proc.terminate()
                        proc.wait(timeout=5)
                    except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
                        pass  # Root timeout independently bounds the recorder's lifetime.
        if code != 0:
            raise RuntimeError(f"Запись не удалась (код {code}): {log_path.read_text().strip()}")
        samples.append(snapshot(pid, original))
        if temporary.stat().st_size < 512:
            raise RuntimeError("perf не записал пригодный профиль.")
        data = output / f"{args.phase}.data"
        report_path = output / f"{args.phase}.txt"
        report_path.unlink(missing_ok=True)  # Never pair an old report with new raw data.
        temporary.replace(data)
        metadata = {"pid": pid, "identity": original, "command": command,
                    "comparison_note": comparison_note,
                    "samples": samples, "sched_schedstats": Path("/proc/sys/kernel/sched_schedstats").read_text().strip()}
        (output / f"{args.phase}.json").write_text(json.dumps(metadata, indent=2))
        (output / f"{args.phase}.maps.txt").write_text(maps_before)
        (output / f"{args.phase}.maps-end.txt").write_text(Path(f"/proc/{pid}/maps").read_text())
        print("ЗАПИСЬ ЗАВЕРШЕНА. Формирую отчёт.", flush=True)
        report = f"{args.phase}: PID {pid}, {samples[0]['utc']}\nExecutable: {original[2]}\n\n"
        if comparison_note:
            report += comparison_note + "\n\n"
        report += thread_summary(samples[0], samples[-1])
        report += "\n\n=== Native functions / user CPU time ===\n" + perf_report(data, pid, "dso,symbol")
        report += "\n\n=== CPU / thread distribution ===\n" + perf_report(data, pid, "cpu,pid,comm")
        report += "\n\nПрофиль не показывает off-CPU ожидания и имена функций внутри анонимного JIT-кода.\n"
        report_path.write_text(report)
        print(f"ГОТОВО: {report_path}", flush=True)
        print("Сбор остановлен. Повтор той же фазы заменит только её предыдущие результаты.", flush=True)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nЗамер отменён. Настройки CS2 не менялись.", file=sys.stderr)
        sys.exit(130)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        sys.exit(1)
