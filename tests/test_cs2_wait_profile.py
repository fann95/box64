"""Offline fixtures for bounded CS2 scheduling profiles; no perf privileges needed."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cs2_wait_profile import analyze_events, build_record_command, parse_script, probe, report, recording_errors


def switch(time, prev, state, next_tid, stack=()):
    text = (f" cs2 100/{prev} [003] {time}: sched:sched_switch: "
            f"prev_comm=cs2 prev_pid={prev} prev_prio=120 prev_state={state} ==> "
            f"next_comm=task next_pid={next_tid} next_prio=120\n")
    return text + "".join(f"        {pc:016x} function (/lib/test.so)\n" for pc in stack) + "\n"


def wake(time, tid):
    return (f" other 300/300 [004] {time}: sched:sched_wakeup: "
            f"comm=cs2 pid={tid} prio=120 target_cpu=003\n\n")


class WaitProfileTests(unittest.TestCase):
    def analyze(self, text, start=100, end=101):
        return analyze_events(parse_script(text), 100, 200, window_start=start, window_end=end)

    def test_sleep_and_runnable_delay(self):
        text = switch("100.100000001", 100, "S", 300, [0xf1234560, 0xe1234560])
        text += wake("100.300000001", 100)
        text += switch("100.400000001", 300, "R", 100, [0xdeadcafe])
        result = self.analyze(text)
        self.assertTrue(result["reliable"])
        item, = result["intervals"]
        self.assertEqual(item["start_ns"], 100100000001)
        self.assertEqual(item["end_ns"], 100400000001)
        self.assertEqual(item["duration_ns"], 300000000)
        self.assertEqual(item["sleep_ns"], 200000000)
        self.assertEqual(item["runnable_ns"], 100000000)
        self.assertEqual(item["stack_ips"], [0xf1234560, 0xe1234560])
        self.assertNotIn(0xdeadcafe, item["stack_ips"])
        self.assertEqual(item["stack_timestamp_ns"], item["start_ns"])

    def test_libtraceevent_compact_format_with_inline_kernel_ip(self):
        text = (
            " cs2 100/100 [018] 100.100000001: sched:sched_switch: "
            "cs2:100 [120] S ==> worker: with spaces:300 [120] ffffab4b86f97ae4 [unknown] ([kernel.kallsyms])\n"
            "        0000fc3003e19008 guest ([unknown])\n"
            " swapper 0/0 [019] 100.300000001: sched:sched_wakeup: "
            "cs2:100 [120] CPU:018 ffffab4b86f96ba0 [unknown] ([kernel.kallsyms])\n"
            " migration/18 126/126 [018] 100.400000001: sched:sched_switch: "
            "migration/18:126 [0] R+ ==> cs2:100 [120] ffffab4b86f97ae4 [unknown] ([kernel.kallsyms])\n"
        )
        result = self.analyze(text)
        self.assertTrue(result["reliable"], result["errors"])
        item, = result["intervals"]
        self.assertEqual(item["sleep_ns"], 200000000)
        self.assertEqual(item["runnable_ns"], 100000000)
        self.assertEqual(item["stack_ips"], [0xfc3003e19008])

    def test_r_and_preempted_r_are_not_sleep(self):
        for state in ("R", "R+"):
            with self.subTest(state=state):
                result = self.analyze(switch("100.1", 200, state, 300) +
                                      switch("100.4", 300, "S", 200))
                item, = result["intervals"]
                self.assertEqual(item["sleep_ns"], 0)
                self.assertEqual(item["runnable_ns"], 300000000)
                self.assertTrue(result["reliable"])

    def test_two_switch_events_are_deduplicated_without_losing_stack(self):
        # Selected main switches to selected AudioMixer: both filters match.
        text = switch("100.1", 100, "S", 200)
        text += switch("100.1", 100, "S", 200, [0xcafebabe])
        text += wake("100.2", 100) + switch("100.3", 200, "R+", 100)
        parsed = parse_script(text)
        self.assertEqual(len(parsed["events"]), 3)
        result = analyze_events(parsed, 100, 200, window_start=100, window_end=101)
        main = next(item for item in result["intervals"] if item["tid"] == 100)
        self.assertEqual(main["stack_ips"], [0xcafebabe])
        self.assertEqual(main["sleep_ns"], 100000000)
        self.assertTrue(result["reliable"])

    def test_window_edges_are_censored_and_excluded_from_complete_totals(self):
        text = wake("100.1", 100) + switch("100.2", 300, "R", 100)
        text += switch("100.9", 100, "D", 300, [0x12345678])
        result = self.analyze(text)
        first, last = result["intervals"]
        self.assertTrue(first["censored_left"])
        self.assertEqual(first["runnable_ns"], 100000000)
        self.assertEqual(first["unattributed_ns"], 100000000)
        self.assertTrue(last["censored_right"])
        self.assertEqual(last["sleep_ns"], 100000000)
        self.assertEqual(result["threads"]["100"]["complete_interval_count"], 0)
        self.assertEqual(result["threads"]["100"]["complete_offcpu_ns"], 0)
        self.assertEqual(result["threads"]["100"]["censored_offcpu_ns"], 300000000)

    def test_missing_wakeup_is_unknown_not_assumed_sleep(self):
        result = self.analyze(switch("100.1", 100, "S", 300) +
                              switch("100.3", 300, "R", 100))
        item, = result["intervals"]
        self.assertIsNone(item["sleep_ns"])
        self.assertIsNone(item["runnable_ns"])
        self.assertEqual(item["unattributed_ns"], 200000000)
        self.assertIn("missing_wakeup", item["flags"])
        self.assertFalse(result["reliable"])

    def test_loss_and_truncated_sequences_are_unreliable(self):
        text = switch("100.1", 100, "S", 300)
        text += "PERF_RECORD_LOST lost 23 events\n"
        text += switch("100.3", 100, "R", 300)
        result = self.analyze(text)
        self.assertFalse(result["reliable"])
        self.assertEqual(len(result["lost_records"]), 1)
        self.assertIn("missing_switch_in", result["intervals"][0]["flags"])
        self.assertTrue(result["intervals"][0]["censored_right"])

    def test_absolute_monotonic_clock_and_nanosecond_precision(self):
        result = self.analyze(switch("28701.000000001", 100, "R", 300) +
                              switch("28701.000000008", 300, "S", 100),
                              start="28701.000000000", end="28702.000000000")
        item, = result["intervals"]
        self.assertEqual(item["duration_ns"], 7)
        self.assertEqual(result["clock"], "CLOCK_MONOTONIC")
        self.assertEqual(result["window_start_ns"], 28701000000000)

    def test_command_keeps_both_switch_directions_in_one_event(self):
        command = build_record_command(100, 200, "/tmp/waits.data", privilege_prefix=())
        events = [command[i + 1] for i, item in enumerate(command) if item == "-e"]
        filters = [command[i + 1] for i, item in enumerate(command) if item == "--filter"]
        self.assertEqual(events, ["sched:sched_switch/call-graph=no/",
                                  "sched:sched_wakeup/call-graph=no/"])
        self.assertEqual(filters, ["prev_pid == 100 || prev_pid == 200 || next_pid == 100 || next_pid == 200",
                                   "pid == 100 || pid == 200"])
        self.assertEqual(command[command.index("--clockid") + 1], "mono")
        self.assertEqual(command[command.index("--delay") + 1], "0-10000")
        self.assertEqual(command[command.index("--max-size") + 1], "64M")
        self.assertEqual(command[-3:], ["--", "sleep", "10.0"])
        self.assertNotIn("-p", command)
        self.assertNotIn("-t", command)
        self.assertNotIn("--user-callchains", command)
        for duration in (0, -1, 11, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                build_record_command(100, 200, "/tmp/waits.data", duration=duration)

    def test_perf_dropped_event_is_failure_even_with_zero_exit_status(self):
        log = ("Error:\nFailure to open event 'sched:sched_switchH' on PMU 'tracepoint' "
               "which will be removed.\nsched:sched_switchH: PMU Hardware doesn't support "
               "sampling/overflow-interrupts. Try 'perf stat'\nEvents disabled\n"
               "[ perf record: Captured and wrote 3,626 MB /tmp/wait.data ]\n")
        self.assertTrue(recording_errors(0, log))
        self.assertEqual(recording_errors(0, "[ perf record: Captured and wrote 1 MB ]\n"), [])
        self.assertTrue(recording_errors(1, ""))

    def test_unavailable_probe_reports_error_without_password_prompt(self):
        failed = SimpleNamespace(returncode=1, stdout="", stderr="sudo: a password is required\n")
        with patch("cs2_wait_profile.subprocess.run", return_value=failed) as run:
            result = probe()
        self.assertFalse(result["ready"])
        self.assertFalse(result["event_open_validated"])
        self.assertIn("password", result["errors"][0])
        self.assertEqual(run.call_args.args[0][:3], ["sudo", "-n", "cat"])
        self.assertEqual(run.call_count, 1)

    def test_partial_perf_script_failure_keeps_data_but_is_unreliable(self):
        partial = SimpleNamespace(returncode=1,
                                  stdout=switch("100.1", 100, "R", 300) +
                                  switch("100.3", 300, "S", 100),
                                  stderr="failed to process truncated file\n")
        with patch("cs2_wait_profile.subprocess.run", return_value=partial):
            result = report("/tmp/example.data", 100, 200, window_start=100, window_end=101)
        self.assertFalse(result["reliable"])
        self.assertEqual(result["intervals"][0]["runnable_ns"], 200000000)
        self.assertEqual(result["raw_script"], partial.stdout)
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
