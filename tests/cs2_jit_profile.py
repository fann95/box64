#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, time-aware decoder for Box64's optional JIT profile journal."""

from bisect import bisect_left, bisect_right, insort
from dataclasses import dataclass
import os
from pathlib import Path
import re
import struct


MAX_JOURNAL_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_ELF_TABLE_BYTES = 64 * 1024 * 1024
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_CPU_LINE = re.compile(
    r"^\s*(?P<comm>.*?)\s+(?P<pid>\d+)(?:/|\s+)(?P<tid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+(?P<seconds>\d+)\.(?P<frac>\d{1,9}):?\s+"
    r"(?P<ip>(?:0x)?[0-9a-fA-F]+)\s+\((?P<dso>.*)\)\s*$")


def parse_cpu_script(text):
    """Parse `perf script --ns -F comm,pid,tid,cpu,time,ip,dso` losslessly."""
    samples, errors, unparsed = [], [], 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _CPU_LINE.match(line)
        if not match:
            unparsed += 1
            if len(errors) < 20:
                errors.append(f"perf script line {number}: unrecognized sample format")
            continue
        values = match.groupdict()
        samples.append({"comm": values["comm"], "pid": int(values["pid"]),
                        "tid": int(values["tid"]), "cpu": int(values["cpu"]),
                        "time_ns": int(values["seconds"]) * 1_000_000_000
                        + int(values["frac"].ljust(9, "0")),
                        "ip": int(values["ip"], 16), "dso": values["dso"]})
    return {"samples": samples, "errors": errors, "unparsed": unparsed}


def _hex(value):
    if not _HEX.fullmatch(value) or len(value) > 16:
        raise ValueError("invalid hexadecimal integer")
    return int(value, 16)


def _decimal(value):
    if not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise ValueError("invalid decimal integer")
    return int(value)


def instruction_spans(encoded, native_size, guest_size, prefix):
    """Return native exclusive ends and corresponding guest instruction offsets.

    A zero following a nibble of 15 completes that instruction; a separate
    zero at the next instruction boundary terminates the table.
    """
    if not encoded or len(encoded) % 2 or not _HEX.fullmatch(encoded):
        raise ValueError("invalid instruction-size bytes")
    raw = bytes.fromhex(encoded)
    ends, guests = ([prefix], [0]) if prefix else ([], [])
    native, guest, position = prefix, 0, 0
    terminated = False
    while position < len(raw):
        if raw[position] == 0:
            position += 1
            terminated = True
            break
        guest_length = native_length = 0
        while True:
            if position == len(raw):
                raise ValueError("incomplete instruction-size continuation")
            value = raw[position]
            position += 1
            guest_length += value & 15
            native_length += (value >> 4) * 4
            if (value & 15) != 15 and (value >> 4) != 15:
                break
        native += native_length
        if native_length:
            ends.append(native)
            guests.append(guest)
        guest += guest_length
    if not terminated or position != len(raw):
        raise ValueError("missing or misplaced instruction-size terminator")
    # The hashed source range can retain trailing dead code pruned before emit.
    if not guest or guest > guest_size or native > native_size or prefix > native_size:
        raise ValueError("instruction-size totals disagree with block sizes")
    return ends, guests


@dataclass
class Block:
    start: int
    size: int
    guest: int
    ends: list
    guests: list

    def translate(self, address):
        position = bisect_right(self.ends, address - self.start)
        return self.guest + self.guests[position] if position < len(self.ends) else None


class Journal:
    """Bounded streaming reader; a bad suffix invalidates subsequent samples."""

    def __init__(self, path, expected_pid):
        self.path = Path(path)
        self.expected_pid = expected_pid
        self.errors = []
        self.start_ns = None
        self.last_ns = None
        self.trusted_until = None
        self.records = 0

    def fail(self, message, cutoff=None):
        self.errors.append(message)
        self.trusted_until = cutoff if cutoff is not None else (self.last_ns or 0)

    def events(self):
        try:
            with self.path.open("rb") as source:
                if os.fstat(source.fileno()).st_size > MAX_JOURNAL_BYTES:
                    self.fail("JIT journal exceeds 128 MiB limit", 0)
                    return
                consumed = 0
                for number in range(1, MAX_JOURNAL_BYTES + 1):
                    raw = source.readline(MAX_RECORD_BYTES + 1)
                    if not raw:
                        break
                    consumed += len(raw)
                    if consumed > MAX_JOURNAL_BYTES or len(raw) > MAX_RECORD_BYTES:
                        raise ValueError("journal or record size limit exceeded")
                    if not raw.endswith(b"\n"):
                        raise ValueError("truncated final journal record")
                    fields = raw[:-1].decode("ascii").split("\t")
                    if number == 1:
                        if len(fields) != 4 or fields[:2] != ["V", "1"]:
                            raise ValueError("missing or unsupported journal header")
                        if _decimal(fields[2]) != self.expected_pid:
                            raise ValueError("journal PID does not match sampled process")
                        self.start_ns = self.last_ns = _decimal(fields[3])
                        continue
                    if len(fields) < 2:
                        raise ValueError("missing journal timestamp")
                    timestamp = _decimal(fields[1])
                    if timestamp < self.last_ns:
                        self.fail("JIT journal timestamps moved backwards; chronology is untrusted", 0)
                        return
                    kind = fields[0]
                    if kind == "L" and len(fields) == 8:
                        start, size, guest, guest_size, prefix = map(_hex, fields[2:7])
                        if not size or not guest_size or start + size > 1 << 64 or guest + guest_size > 1 << 64:
                            raise ValueError("invalid block address range")
                        ends, guests = instruction_spans(fields[7], size, guest_size, prefix)
                        payload = Block(start, size, guest, ends, guests)
                    elif kind == "U" and len(fields) == 4:
                        payload = (_hex(fields[2]), _hex(fields[3]))
                        if not payload[1] or sum(payload) > 1 << 64:
                            raise ValueError("invalid unload address range")
                    elif kind == "E" and len(fields) == 3:
                        self.last_ns = timestamp
                        self.fail(f"JIT writer stopped: {fields[2]}", timestamp)
                        return
                    else:
                        raise ValueError("unknown or malformed journal record")
                    self.records += 1
                    self.last_ns = timestamp
                    yield timestamp, kind, payload
                if self.start_ns is None:
                    self.fail("empty JIT journal", 0)
        except (OSError, UnicodeError, ValueError) as error:
            self.fail(f"JIT journal: {error}")


@dataclass(frozen=True)
class Mapping:
    start: int
    end: int
    permissions: str
    offset: int
    major: int
    minor: int
    inode: int
    path: str


def parse_maps(text):
    mappings, errors = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            fields = line.split(None, 5)
            start, end = (int(x, 16) for x in fields[0].split("-"))
            major, minor = (int(x, 16) for x in fields[3].split(":"))
            path = fields[5] if len(fields) == 6 else ""
            path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), path)
            if start >= end or len(fields[1]) != 4:
                raise ValueError("invalid map range or permissions")
            mappings.append(Mapping(start, end, fields[1], int(fields[2], 16),
                                    major, minor, int(fields[4]), path))
        except (ValueError, IndexError):
            errors.append(f"maps line {number}: malformed mapping")
    return mappings, errors


class ELFImage:
    """Read PT_LOAD and bounded ELF64 symbol tables once per mapped file."""

    def __init__(self, mapping):
        self.loads = []
        self.symbols = []
        self.symbol_starts = []
        self.symbol_max_ends = []
        self.symbol_error = None
        with open(mapping.path, "rb") as source:
            initial = os.fstat(source.fileno())
            if (initial.st_ino, os.major(initial.st_dev), os.minor(initial.st_dev)) != (
                    mapping.inode, mapping.major, mapping.minor):
                raise ValueError("mapped file identity changed (device/inode mismatch)")

            def read_at(offset, length):
                if offset < 0 or length < 0 or offset + length > initial.st_size:
                    raise ValueError("ELF table lies outside file")
                source.seek(offset)
                data = source.read(length)
                if len(data) != length:
                    raise ValueError("short ELF read")
                return data

            header = read_at(0, 64)
            if header[:6] != b"\x7fELF\x02\x01":
                raise ValueError("not a little-endian ELF64 file")
            values = struct.unpack("<HHIQQQIHHHHHH", header[16:])
            if values[0] not in (2, 3):
                raise ValueError("ELF is not an executable or shared object")
            phoff, shoff, phsize, phnum, shsize, shnum = (
                values[4], values[5], values[8], values[9], values[10], values[11])
            if phsize < 56 or phnum > 4096:
                raise ValueError("unsupported ELF program header table")
            for index in range(phnum):
                segment = struct.unpack("<IIQQQQQQ", read_at(phoff + index * phsize, 56))
                if segment[0] == 1:
                    self.loads.append(segment)
            if not self.loads:
                raise ValueError("ELF has no PT_LOAD segments")
            try:
                if shnum and shsize < 64:
                    raise ValueError("unsupported ELF section header table")
                sections = [struct.unpack("<IIQQQQIIQQ", read_at(shoff + index * shsize, 64))
                            for index in range(shnum)]
                table_budget = MAX_ELF_TABLE_BYTES
                strings = {}
                for section in sections:
                    if section[1] not in (2, 11):
                        continue
                    offset, length, link, entry = section[4], section[5], section[6], section[9]
                    if entry < 24 or length % entry or link >= len(sections):
                        raise ValueError("malformed ELF symbol table")
                    table_budget -= length
                    if table_budget < 0:
                        raise ValueError("ELF symbol tables exceed 64 MiB limit")
                    if link not in strings:
                        string_section = sections[link]
                        table_budget -= string_section[5]
                        if table_budget < 0 or string_section[1] != 3:
                            raise ValueError("invalid or oversized ELF string table")
                        strings[link] = read_at(string_section[4], string_section[5])
                    names = strings[link]
                    entries = read_at(offset, length)
                    for position in range(0, length, entry):
                        name, info, _, section_index, value, size = struct.unpack_from("<IBBHQQ", entries, position)
                        if (info & 15) not in (2, 10) or not section_index or not size or name >= len(names):
                            continue
                        name_end = names.find(b"\0", name)
                        if name_end < 0:
                            raise ValueError("unterminated ELF symbol name")
                        symbol = names[name:name_end].decode("utf-8", "replace")
                        if symbol:
                            self.symbols.append((value, value + size, symbol))
            except (ValueError, struct.error) as error:
                self.symbols.clear()
                self.symbol_error = str(error)
            final = os.fstat(source.fileno())
            if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                    final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                raise ValueError("ELF file changed while reading")
        self.symbols = sorted(set(self.symbols))
        maximum = 0
        for start, end, _ in self.symbols:
            self.symbol_starts.append(start)
            maximum = max(maximum, end)
            self.symbol_max_ends.append(maximum)

    def address(self, mapping, address):
        file_offset = mapping.offset + address - mapping.start
        candidates = set()
        for _, flags, offset, virtual, _, file_size, _, _ in self.loads:
            if "x" in mapping.permissions and not flags & 1:
                continue
            if offset <= file_offset < offset + file_size:
                candidates.add(virtual + file_offset - offset)
        if len(candidates) != 1:
            return None
        return candidates.pop()

    def symbol(self, address):
        position = bisect_right(self.symbol_starts, address) - 1
        while position >= 0 and self.symbol_max_ends[position] > address:
            start, end, name = self.symbols[position]
            if start <= address < end:
                return name, address - start
            position -= 1
        return None, None


class Symbolizer:
    def __init__(self, before, after):
        first, first_errors = parse_maps(before)
        last, last_errors = parse_maps(after)
        stable = set(first) & set(last)
        self.maps = sorted(stable, key=lambda item: item.start)
        self.starts = [item.start for item in self.maps]
        self.images = {}
        self.errors = first_errors + last_errors
        self.unstable = len(set(first) | set(last)) - len(stable)

    def resolve(self, address):
        result = {"module": None, "elf_offset": None, "symbol": None,
                  "symbol_offset": None, "load_bias": None}
        position = bisect_right(self.starts, address) - 1
        if position < 0:
            return result
        mapping = self.maps[position]
        if address >= mapping.end or not mapping.path.startswith("/") or not mapping.inode:
            return result
        # A filename alone cannot prove which bytes were mapped after replacement.
        key = (mapping.path, mapping.inode, mapping.major, mapping.minor)
        if key not in self.images:
            try:
                if mapping.path.endswith(" (deleted)"):
                    raise ValueError("mapped file was deleted")
                self.images[key] = ELFImage(mapping)
                if self.images[key].symbol_error:
                    self.errors.append(f"{mapping.path}: {self.images[key].symbol_error}; symbols unavailable")
            except (OSError, ValueError, struct.error) as error:
                self.images[key] = None
                self.errors.append(f"{mapping.path}: {error}")
        image = self.images[key]
        if image is None:
            return result
        offset = image.address(mapping, address)
        result["module"] = mapping.path
        if offset is not None:
            result["elf_offset"] = offset
            result["load_bias"] = address - offset
            result["symbol"], result["symbol_offset"] = image.symbol(offset)
        return result


def _label(fields, address, guest):
    module = fields["module"]
    if module and fields["symbol"]:
        suffix = f"+0x{fields['symbol_offset']:x}" if fields["symbol_offset"] else ""
        return f"{Path(module).name}!{fields['symbol']}{suffix}"
    if module and fields["elf_offset"] is not None:
        return f"{Path(module).name}+0x{fields['elf_offset']:x}"
    return f"{'guest' if guest else 'native'} 0x{address:x}"


def decode_samples(journal_path, samples, maps_before, maps_after, expected_pid):
    """Annotate samples using journal lifetimes and stable, verified ELF mappings.

    `time_ns` uses CLOCK_MONOTONIC, and `ip` is an integer or hexadecimal string.
    `elf_offset` is an ELF virtual address, not a file offset or map-relative offset.
    A writer error or incomplete suffix sets an explicit temporal trust boundary.
    """
    journal = Journal(journal_path, expected_pid)
    symbols = Symbolizer(maps_before, maps_after)
    starts, blocks, pending, output, errors = [], {}, [], [None] * len(samples), []
    coverage = {"total": len(samples), "guest_mapped": 0, "guest_symbolized": 0,
                "guest_module_only": 0, "native": 0, "unresolved": 0,
                "unstable_mappings": symbols.unstable, "unmatched_unloads": 0}
    for index, sample in enumerate(samples):
        row = dict(sample)
        try:
            address = int(row["ip"], 16) if isinstance(row["ip"], str) else int(row["ip"])
            timestamp = int(row["time_ns"])
            if not 0 <= address < 1 << 64 or timestamp < 0:
                raise ValueError("negative timestamp or invalid address")
            if "pid" in row and int(row["pid"]) != expected_pid:
                raise ValueError("sample PID does not match journal process")
            row.update(ip=address, time_ns=timestamp)
            pending.append((timestamp, index, row))
        except (KeyError, TypeError, ValueError) as error:
            row.update(guest_ip=None, module=None, elf_offset=None, symbol=None,
                       label="invalid sample", kind="unresolved", jit_status="invalid_sample")
            output[index] = row
            errors.append(f"sample {index}: {error}")
    pending.sort(key=lambda item: (item[0], item[1]))
    cursor = 0

    def annotate(item):
        timestamp, index, row = item
        address = row["ip"]
        guest = None
        status = "not_mapped"
        unavailable = journal.start_ns is None or (
            journal.trusted_until is not None and timestamp >= journal.trusted_until)
        if unavailable:
            status = "journal_unavailable"
        elif timestamp < journal.start_ns:
            status = "before_journal"
        else:
            position = bisect_right(starts, address) - 1
            if position >= 0:
                block = blocks[starts[position]]
                if address < block.start + block.size:
                    guest = block.translate(address)
                    status = "mapped" if guest is not None else "outside_instruction_map"
        row["guest_ip"] = guest
        row["jit_status"] = status
        row.update(symbols.resolve(guest if guest is not None else address))
        row["label"] = _label(row, guest if guest is not None else address, guest is not None)
        if guest is not None:
            row["kind"] = "guest"
        elif unavailable or status == "outside_instruction_map":
            row["kind"] = "unresolved"
        else:
            row["kind"] = "native"
        output[index] = row

    for timestamp, kind, payload in journal.events():
        while cursor < len(pending) and pending[cursor][0] < timestamp:
            annotate(pending[cursor])
            cursor += 1
        if kind == "L":
            position = bisect_left(starts, payload.start)
            if ((position and blocks[starts[position - 1]].start + blocks[starts[position - 1]].size > payload.start)
                    or (position < len(starts) and starts[position] < payload.start + payload.size)):
                journal.fail("overlapping live JIT blocks; missing unload record", timestamp)
                break
            insort(starts, payload.start)
            blocks[payload.start] = payload
        else:
            start, size = payload
            if start not in blocks:
                coverage["unmatched_unloads"] += 1
                continue
            if blocks[start].size != size:
                journal.fail("JIT unload size does not match live block", timestamp)
                break
            del blocks[start]
            starts.pop(bisect_left(starts, start))
    while cursor < len(pending):
        annotate(pending[cursor])
        cursor += 1
    # A timestamp regression can invalidate rows emitted before it was discovered.
    if journal.trusted_until is not None:
        for index, row in enumerate(output):
            if (row["jit_status"] not in ("invalid_sample", "journal_unavailable")
                    and row["time_ns"] >= journal.trusted_until):
                annotate((row["time_ns"], index, row))
    for row in output:
        if row["kind"] == "guest":
            coverage["guest_mapped"] += 1
            if row["symbol"]:
                coverage["guest_symbolized"] += 1
            elif row["module"] and row["elf_offset"] is not None:
                coverage["guest_module_only"] += 1
        else:
            coverage[row["kind"]] += 1
    coverage.update(journal_start_ns=journal.start_ns, journal_records=journal.records,
                    journal_trusted_until_ns=journal.trusted_until)
    return {"samples": output, "coverage": coverage,
            "errors": errors + journal.errors + symbols.errors}
