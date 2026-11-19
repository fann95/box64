#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded CS2 CPU/JIT and scheduler profiles; never attach a debugger to the game."""
import argparse
import collections
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from cs2_perf_snapshot import find_game, identity, checked_identity, snapshot, thread_summary
from cs2_jit_profile import decode_samples, parse_cpu_script
import cs2_wait_profile as waits

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "build/cs2-profile/detailed"
JOURNALS = ROOT / "build/cs2-profile/jit"
LIMIT = 128 * 1024 * 1024


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def journal_for(pid, original):
    path = JOURNALS / f"jit-{pid}.maplog"
    with path.open() as f:
        fields = f.readline(1024).strip().split("\t")
    if len(fields) != 4 or fields[:3] != ["V", "1", str(pid)]:
        raise RuntimeError(f"Неверный заголовок JIT-журнала: {path}")
    if int(fields[3]) < original[1] * 1_000_000_000 // os.sysconf("SC_CLK_TCK"):
        raise RuntimeError("JIT-журнал относится к прежнему процессу с таким PID.")
    with path.open("rb") as f:
        size = os.fstat(f.fileno()).st_size
        f.seek(max(0, size - 4096))
        for line in f.read(4096).splitlines():
            if line.startswith(b"E\t"):
                reason = line.split(b"\t", 2)[-1].decode("ascii", "replace")
                raise RuntimeError(f"JIT-журнал уже остановлен ({reason}); этот запуск не даст привязку функций. Запись perf не начата.")
    return path


def copy_journal(source, dest):
    with source.open("rb") as src, dest.open("wb") as out:
        size = os.fstat(src.fileno()).st_size
        if size > LIMIT + 4096:
            raise RuntimeError("JIT-журнал превышает установленный предел.")
        remaining = size
        while remaining:
            part = src.read(min(1024 * 1024, remaining))
            if not part:
                raise RuntimeError("JIT-журнал изменился при копировании.")
            out.write(part)
            remaining -= len(part)


def cpu_command(pid, path, seconds):
    return ["sudo", "-n", "timeout", "-s", "INT", "-k", "3s", f"{seconds + 5}s",
            "perf", "record", "--clockid", "mono", "-e", "cpu-clock:u", "-F", "99",
            "--sample-cpu", "-T", "--no-buildid", "--no-buildid-cache", "--max-size", "32M",
            "-p", str(pid), "-o", str(path), "--", "sleep", str(seconds)]


def limited_wait_command(main, mixer, path, seconds):
    command = waits.build_record_command(main, mixer, path, duration=seconds)
    assert command[:2] == ["sudo", "-n"]
    return command[:2] + ["timeout", "-s", "INT", "-k", "3s", f"{seconds + 5}s"] + command[2:]


def summarize(cpu, scheduler, samples, pid, mixer):
    lines = ["CS2: CPU / JIT / ожидания", "", thread_summary(samples[0], samples[-1]),
             "", "Соответствие JIT-адресов:", json.dumps(cpu["coverage"], ensure_ascii=False)]
    for error in cpu.get("errors", []):
        lines.append("ОГРАНИЧЕНИЕ JIT: " + error)
    for title, selected in [("Все потоки", cpu["samples"]),
                            ("Основной поток", [s for s in cpu["samples"] if s["tid"] == pid]),
                            ("AudioMixer", [s for s in cpu["samples"] if s["tid"] == mixer])]:
        lines += ["", title + ":"]
        modules = collections.Counter(s.get("module") or s.get("dso") or "unknown" for s in selected)
        for module, count in modules.most_common(12):
            lines.append(f"{100 * count / max(len(selected), 1):6.2f}% {count:5d} {module}")
        lines.append("Частые адреса/символы:")
        labels = collections.Counter(s.get("label") or hex(s["ip"]) for s in selected)
        for label, count in labels.most_common(20):
            lines.append(f"{count:5d} {label}")
    lines += ["", "Ожидания выбранных потоков:",
              json.dumps(scheduler.get("threads", {}), ensure_ascii=False, indent=2),
              f"Надёжность последовательности scheduler events: {scheduler.get('reliable', False)}"]
    scheduler_errors = scheduler.get("errors", [])
    for error in scheduler_errors[:10]:
        lines.append("ОГРАНИЧЕНИЕ ОЖИДАНИЙ: " + str(error))
    if len(scheduler_errors) > 10:
        lines.append(f"Всего ошибок последовательности: {len(scheduler_errors)}; подробности в waits.json.")
    for interval in sorted(scheduler.get("intervals", []), key=lambda x: x.get("duration_ns", 0), reverse=True)[:15]:
        lines.append(json.dumps(interval, ensure_ascii=False))
    lines += ["", "Проценты perf отражают CPU-время, а не GPU. Граничные интервалы ожиданий неполны.",
              "Для библиотек без отладочных символов указан модуль и точный ELF-адрес."]
    return "\n".join(lines) + "\n"


def capture(phase, pid, original, seconds):
    checked_identity(pid, original)
    journal = journal_for(pid, original)
    current = snapshot(pid, original)
    mixers = [int(tid) for tid, t in current["threads"].items() if t["name"] == "AudioMixer"]
    if len(mixers) != 1:
        raise RuntimeError(f"Нужен один AudioMixer, найдено: {mixers}. Войди в матч.")
    mixer = mixers[0]
    subprocess.run(["sudo", "-v"], check=True)
    probe = waits.check_recording()
    if not probe.get("ready"):
        write_json(OUTPUT / "scheduler-probe.json", probe)
        raise RuntimeError("События планировщика недоступны. Причина сохранена в detailed/scheduler-probe.json; запись не начата.")
    print(f"{phase}: CS2 PID {pid}, AudioMixer TID {mixer}. Через 10 секунд — запись на {seconds} секунд.", flush=True)
    print("Вернись в матч на передний план; оставь игру открытой до сообщения ГОТОВО.", flush=True)
    time.sleep(10)
    checked_identity(pid, original)
    # AudioMixer can be recreated during map changes.
    current = snapshot(pid, original)
    if str(mixer) not in current["threads"] or current["threads"][str(mixer)]["name"] != "AudioMixer":
        raise RuntimeError("AudioMixer сменился перед записью. Повтори после загрузки карты.")
    before = Path(f"/proc/{pid}/maps").read_text()
    samples = [current]
    with tempfile.TemporaryDirectory(prefix=f".{phase}-", dir=OUTPUT) as work:
        work = Path(work)
        cpu_path, wait_path = work / "cpu.data", work / "wait.data"
        for path in (cpu_path, wait_path):
            path.touch(mode=0o600)
        commands = {"cpu": cpu_command(pid, cpu_path, seconds),
                    "wait": limited_wait_command(pid, mixer, wait_path, seconds)}
        processes, streams = {}, {}
        print("ЗАПИСЬ", flush=True)
        try:
            for name, command in commands.items():
                streams[name] = (work / f"{name}.log").open("w")
                processes[name] = subprocess.Popen(command, stdout=streams[name], stderr=streams[name])
            deadline = time.monotonic() + seconds + 10
            while any(p.poll() is None for p in processes.values()):
                if time.monotonic() > deadline:
                    raise RuntimeError("Превышено ограничение времени записи.")
                time.sleep(1)
                samples.append(snapshot(pid, original))
        finally:
            for process in processes.values():
                if process.poll() is None:
                    process.terminate()  # only sudo/perf; never the game
            for process in processes.values():
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass  # privileged timeout independently bounds recording
            for stream in streams.values():
                stream.close()
            for path in work.iterdir():
                if path.is_file():
                    shutil.copyfile(path, OUTPUT / f"{phase}.{path.name}")
        checked_identity(pid, original)
        after = Path(f"/proc/{pid}/maps").read_text()
        (OUTPUT / f"{phase}.maps.txt").write_text(before)
        (OUTPUT / f"{phase}.maps-end.txt").write_text(after)
        copy_journal(journal, OUTPUT / f"{phase}.jit.maplog")
        metadata = {"pid": pid, "audio_tid": mixer, "identity": original, "phase": phase,
                    "samples": samples, "commands": commands, "probe": probe,
                    "returncodes": {k: p.returncode for k, p in processes.items()}}
        write_json(OUTPUT / f"{phase}.json", metadata)
        if processes["cpu"].returncode:
            raise RuntimeError(f"perf CPU завершился с ошибкой; смотри {phase}.cpu.log.")
        script = subprocess.run(["perf", "script", "--ns", "-i", str(cpu_path), "-F",
                                 "comm,pid,tid,cpu,time,ip,dso"], capture_output=True, text=True, timeout=60)
        if script.returncode:
            raise RuntimeError(script.stderr.strip())
        parsed = parse_cpu_script(script.stdout)
        (OUTPUT / f"{phase}.cpu-script.txt").write_text(script.stdout)
        scheduler = waits.report(wait_path, pid, mixer)
        (OUTPUT / f"{phase}.wait-script.txt").write_text(scheduler.pop("raw_script", ""))
        wait_log = (work / "wait.log").read_text(errors="replace")
        record_errors = waits.recording_errors(processes["wait"].returncode, wait_log)
        if record_errors:
            scheduler["reliable"] = False
            scheduler.setdefault("errors", []).extend(record_errors)
        stack_samples = []
        for index, interval in enumerate(scheduler.get("intervals", [])):
            for ip in interval.get("stack_ips", []):
                stack_samples.append({"ip": ip, "time_ns": interval["stack_timestamp_ns"],
                                      "tid": interval["tid"], "comm": "wait", "interval_index": index})
        decoded = decode_samples(OUTPUT / f"{phase}.jit.maplog", parsed["samples"] + stack_samples,
                                 before, after, pid)
        decoded.setdefault("errors", []).extend(parsed.get("errors", []))
        cpu_samples = decoded["samples"][:len(parsed["samples"])]
        for row in decoded["samples"][len(parsed["samples"]):]:
            scheduler["intervals"][row["interval_index"]].setdefault("decoded_stack", []).append(row.get("label"))
        decoded["samples"] = cpu_samples
        write_json(OUTPUT / f"{phase}.resolved.json", decoded)
        write_json(OUTPUT / f"{phase}.waits.json", scheduler)
        (OUTPUT / f"{phase}.txt").write_text(summarize(decoded, scheduler, samples, pid, mixer))
    print(f"ГОТОВО: {OUTPUT / (phase + '.txt')}", flush=True)
    print("Запись perf остановлена.", flush=True)
    if decoded.get("errors") or not scheduler.get("reliable", False):
        print("Есть ограничения данных; они явно записаны в отчёте.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", nargs="?", choices=("check", "pair", "normal", "slow"), default="slow")
    parser.add_argument("--seconds", type=int, choices=range(5, 11), default=10)
    args = parser.parse_args()
    if os.getuid() == 0:
        raise RuntimeError("Запускай python3 без sudo: помощник запросит пароль только для perf.")
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.phase == "check":
        subprocess.run(["sudo", "-v"], check=True)
        result = waits.check_recording()
        write_json(OUTPUT / "scheduler-probe.json", result)
        if not result["ready"]:
            raise RuntimeError("Проверка perf не прошла: " + "; ".join(result["errors"][:3]))
        print("ГОТОВО: perf записывает уход с CPU, пробуждение и возврат. Проверено на отдельном тестовом процессе; игра не нужна.")
        return
    pid = find_game()
    original = identity(pid)
    try:
        journal_for(pid, original)
    except FileNotFoundError:
        raise RuntimeError("В этом запуске CS2 нет журнала JIT-адресов. Нужен запуск с включённой записью JIT.") from None
    if args.phase == "pair":
        capture("normal", pid, original, args.seconds)
        print("Продолжай играть. При сильном падении FPS вернись сюда и нажми Enter.", flush=True)
        print("Пока ожидаю Enter, perf не работает.", flush=True)
        input()
        checked_identity(pid, original)
        capture("slow", pid, original, args.seconds)
    else:
        capture(args.phase, pid, original, args.seconds)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Ошибка: {error}")
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("Замер отменён. Процесс игры не останавливался.")
