#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline journal and ELF attribution regression tests; no game or perf needed."""

import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import cs2_jit_profile as profile


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.journal = self.root / "journal.tsv"

    def decode(self, records, samples, before="", after=None):
        self.journal.write_bytes(records.encode("ascii"))
        return profile.decode_samples(self.journal, samples, before,
                                      before if after is None else after, 123)

    @staticmethod
    def sample(time, ip=0x1000, **extra):
        return {"time_ns": time, "ip": ip, "tid": 123, "comm": "test worker", **extra}

    def test_load_unload_and_address_reuse(self):
        result = self.decode(
            "V\t1\t123\t10\n"
            "L\t20\t1000\t8\t2000\t4\t0\t121200\n"
            "U\t30\t1000\t8\n"
            "L\t40\t1000\t8\t3000\t4\t0\t121200\n",
            [self.sample(t) for t in [45, 15, 20, 29, 30, 39, 40]])
        self.assertEqual(result["errors"], [])
        self.assertEqual([row["guest_ip"] for row in result["samples"]],
                         [0x3000, None, 0x2000, 0x2000, None, None, 0x3000])
        self.assertEqual(result["coverage"]["guest_mapped"], 4)

    def test_instruction_boundaries_prefix_zero_native_and_padding(self):
        # prefix=4, x86 NOP=2/native=0, x86=3/native=4, x86=1/native=4, padding=4.
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t10\t2000\t6\t4\t02131100\n",
                             [self.sample(21, ip) for ip in [0x1000, 0x1003, 0x1004, 0x1008, 0x100c, 0x1010]])
        self.assertEqual(result["errors"], [])
        self.assertEqual([row["guest_ip"] for row in result["samples"]],
                         [0x2000, 0x2000, 0x2002, 0x2005, None, None])
        self.assertEqual(result["samples"][4]["jit_status"], "outside_instruction_map")
        self.assertEqual(result["samples"][5]["kind"], "native")

    def test_exact_fifteen_requires_continuation_zero_then_terminator(self):
        ends, guests = profile.instruction_spans("f20000", 60, 2, 0)
        self.assertEqual((ends, guests), ([60], [0]))
        ends, guests = profile.instruction_spans("ff001100", 64, 16, 0)
        self.assertEqual((ends, guests), ([60, 64], [0, 15]))
        ends, guests = profile.instruction_spans("f2f01000", 124, 2, 0)
        self.assertEqual((ends, guests), ([124], [0]))
        with self.assertRaisesRegex(ValueError, "terminator"):
            profile.instruction_spans("f200", 60, 2, 0)

    def test_table_totals_and_missing_terminator(self):
        for encoded, size, guest, prefix in [("1200", 4, 1, 0), ("1100", 4, 1, 4),
                                              ("11", 4, 1, 0), ("0011", 4, 1, 0),
                                              ("f1", 60, 1, 0), ("0x1100", 4, 1, 0)]:
            with self.subTest(encoded=encoded, size=size, guest=guest, prefix=prefix):
                with self.assertRaises(ValueError):
                    profile.instruction_spans(encoded, size, guest, prefix)

    def test_hashed_range_can_include_pruned_dead_tail(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t8\t2000\t40\t0\t131200\n",
                             [self.sample(21, ip) for ip in (0x1000, 0x1004, 0x1008)])
        self.assertEqual(result["errors"], [])
        self.assertEqual([row["guest_ip"] for row in result["samples"]],
                         [0x2000, 0x2003, None])

    def test_equal_timestamps_respect_journal_order(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
                             "U\t20\t1000\t4\nL\t20\t1000\t4\t3000\t1\t0\t1100\n",
                             [self.sample(20)])
        self.assertEqual(result["samples"][0]["guest_ip"], 0x3000)

    def test_writer_error_has_time_boundary(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\nE\t30\tlimit\n",
                             [self.sample(29), self.sample(30), self.sample(31)])
        self.assertIn("limit", result["errors"][0])
        self.assertEqual([row["guest_ip"] for row in result["samples"]], [0x2000, None, None])
        self.assertEqual(result["coverage"]["journal_trusted_until_ns"], 30)

    def test_truncated_suffix_does_not_guess_future_mapping(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
                             "U\t30\t1000\t4\nL\t40\t1000\t4\t3000",
                             [self.sample(29), self.sample(31), self.sample(45)])
        self.assertIn("truncated", result["errors"][0])
        self.assertEqual([row["guest_ip"] for row in result["samples"]], [0x2000, None, None])
        self.assertEqual(result["samples"][2]["jit_status"], "journal_unavailable")

    def test_invalid_header_and_pid(self):
        for header in ["", "V\t2\t123\t10\n", "V\t1\t999\t10\n", "L\t10\t1000\t4\t2000\t1\t0\t1100\n"]:
            with self.subTest(header=header):
                result = self.decode(header, [self.sample(30)])
                self.assertTrue(result["errors"])
                self.assertEqual(result["samples"][0]["kind"], "unresolved")

    def test_timestamp_regression_invalidates_already_decoded_samples(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
                             "U\t40\t1000\t4\nL\t15\t1000\t4\t3000\t1\t0\t1100\n",
                             [self.sample(25), self.sample(45)])
        self.assertIn("backwards", result["errors"][0])
        self.assertEqual([row["guest_ip"] for row in result["samples"]], [None, None])
        self.assertEqual(result["coverage"]["guest_mapped"], 0)
        self.assertEqual(result["coverage"]["unresolved"], 2)

    def test_missing_journal(self):
        result = profile.decode_samples(self.root / "missing", [self.sample(30)], "", "", 123)
        self.assertTrue(result["errors"])
        self.assertEqual(result["coverage"]["unresolved"], 1)

    def test_invalid_sample_and_other_pid_keep_positions(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n",
                             [self.sample(30, pid=456), self.sample(30, ip="1000"),
                              {"time_ns": 30}, self.sample(30, ip=-1)])
        self.assertEqual([row["guest_ip"] for row in result["samples"]], [None, 0x2000, None, None])
        self.assertEqual(result["coverage"]["guest_mapped"], 1)
        self.assertEqual(result["coverage"]["unresolved"], 3)
        self.assertEqual(len(result["errors"]), 3)

    def test_size_limits_are_explicit(self):
        text = "V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
        with patch.object(profile, "MAX_JOURNAL_BYTES", 15):
            result = self.decode(text, [self.sample(30)])
            self.assertTrue(result["errors"])
            self.assertIsNone(result["samples"][0]["guest_ip"])
        with patch.object(profile, "MAX_RECORD_BYTES", 20):
            result = self.decode(text, [self.sample(30)])
            self.assertIn("limit", result["errors"][0])
            self.assertIsNone(result["samples"][0]["guest_ip"])

    def test_overlapping_live_block_is_not_silently_replaced(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
                             "L\t30\t1000\t4\t3000\t1\t0\t1100\n",
                             [self.sample(29), self.sample(30), self.sample(31)])
        self.assertIn("overlapping", result["errors"][0])
        self.assertEqual([row["guest_ip"] for row in result["samples"]], [0x2000, None, None])

    def test_unmatched_unload_of_unpublished_block_is_allowed(self):
        result = self.decode("V\t1\t123\t10\nU\t20\t1000\t4\n", [self.sample(30)])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["coverage"]["unmatched_unloads"], 1)

    def test_unload_size_mismatch_invalidates_later_samples(self):
        result = self.decode("V\t1\t123\t10\nL\t20\t1000\t4\t2000\t1\t0\t1100\n"
                             "U\t30\t1000\t8\n", [self.sample(31)])
        self.assertIn("size", result["errors"][0])
        self.assertIsNone(result["samples"][0]["guest_ip"])

    def elf(self, symbols=True):
        path = self.root / "guest module.so"
        data = bytearray(0x2000)
        data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        data[16:64] = struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0x5000, 64, 0x1800,
                                  0, 64, 56, 2, 64, 4 if symbols else 0, 0)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 4, 0, 0, 0, 0x1000, 0x1000, 0x1000)
        struct.pack_into("<IIQQQQQQ", data, 120, 1, 5, 0x1000, 0x5000, 0, 0x1000, 0x1000, 0x1000)
        if symbols:
            names = b"\0function\0next_export\0"
            data[0x1300:0x1300 + len(names)] = names
            struct.pack_into("<IBBHQQ", data, 0x1418, 1, 0x12, 0, 1, 0x5000, 4)
            struct.pack_into("<IBBHQQ", data, 0x1430, 10, 0x12, 0, 1, 0x5020, 4)
            struct.pack_into("<IIQQQQIIQQ", data, 0x1840, 0, 3, 0, 0, 0x1300, len(names), 0, 0, 1, 0)
            struct.pack_into("<IIQQQQIIQQ", data, 0x1880, 0, 11, 0, 0, 0x1400, 72, 1, 0, 8, 24)
        path.write_bytes(data)
        stat = path.stat()
        maps = (f"70000000-70001000 r-xp 00001000 {os.major(stat.st_dev):02x}:{os.minor(stat.st_dev):02x} "
                f"{stat.st_ino} {path}\n")
        return path, maps

    def guest_samples(self, maps, after=None, guest=0x70000002):
        return self.decode(f"V\t1\t123\t10\nL\t20\t1000\t4\t{guest:x}\t1\t0\t1100\n",
                           [self.sample(30)], maps, after)

    def test_elf_load_bias_and_symbol_with_spaces_in_path(self):
        path, maps = self.elf()
        result = self.guest_samples(maps)
        row = result["samples"][0]
        self.assertEqual(result["errors"], [])
        self.assertEqual(row["module"], str(path))
        self.assertEqual(row["elf_offset"], 0x5002)
        self.assertEqual(row["load_bias"], 0x6fffb000)
        self.assertEqual(row["symbol"], "function")
        self.assertEqual(row["label"], "guest module.so!function+0x2")

    def test_stripped_private_function_does_not_inherit_nearest_export(self):
        _, maps = self.elf()
        result = self.guest_samples(maps, guest=0x70000010)
        row = result["samples"][0]
        self.assertEqual(row["elf_offset"], 0x5010)
        self.assertIsNone(row["symbol"])
        self.assertEqual(row["label"], "guest module.so+0x5010")
        self.assertEqual(result["coverage"]["guest_module_only"], 1)

    def test_fully_stripped_elf_keeps_module_offset(self):
        _, maps = self.elf(symbols=False)
        result = self.guest_samples(maps)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["samples"][0]["label"], "guest module.so+0x5002")

    def test_changed_maps_do_not_attribute_module(self):
        _, maps = self.elf()
        result = self.guest_samples(maps, maps.replace("r-xp", "r--p"))
        self.assertIsNone(result["samples"][0]["module"])
        self.assertEqual(result["coverage"]["unstable_mappings"], 2)

    def test_replaced_or_missing_file_is_unresolved(self):
        for replacement in [False, True]:
            with self.subTest(replacement=replacement):
                path, maps = self.elf()
                path.rename(self.root / "saved inode")
                if replacement:
                    path.write_bytes((self.root / "saved inode").read_bytes())
                result = self.guest_samples(maps)
                self.assertTrue(result["errors"])
                self.assertIsNone(result["samples"][0]["module"])
                (self.root / "saved inode").unlink()

    def test_bad_symbol_table_keeps_valid_pt_load_offset(self):
        path, maps = self.elf()
        data = bytearray(path.read_bytes())
        struct.pack_into("<Q", data, 0x1880 + 32, 0xffffff)
        path.write_bytes(data)
        result = self.guest_samples(maps)
        self.assertTrue(result["errors"])
        self.assertEqual(result["samples"][0]["label"], "guest module.so+0x5002")

    def test_native_address_is_never_claimed_as_guest(self):
        _, maps = self.elf()
        result = self.decode("V\t1\t123\t10\n", [self.sample(30, 0x70000002)], maps)
        row = result["samples"][0]
        self.assertEqual(row["kind"], "native")
        self.assertIsNone(row["guest_ip"])
        self.assertEqual(row["symbol"], "function")

    def test_parse_perf_cpu_preserves_nanoseconds_and_spaces(self):
        result = profile.parse_cpu_script(
            "             cs2 render worker  655709/655710  [012] 28701.308652464:      f9da7928d140 (/tmp/perf-655709.map)\n"
            " cs2 655709 655711 [001] 28702.1: 0x12 ([unknown])\n"
            "# comment\n\nBAD\n")
        self.assertEqual(result["samples"][0], {
            "comm": "cs2 render worker", "pid": 655709, "tid": 655710, "cpu": 12,
            "time_ns": 28701308652464, "ip": 0xf9da7928d140, "dso": "/tmp/perf-655709.map"})
        self.assertEqual(result["samples"][1]["time_ns"], 28702100000000)
        self.assertEqual(result["unparsed"], 1)
        self.assertEqual(len(result["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
