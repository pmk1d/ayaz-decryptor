import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("search_runner", Path(__file__).with_name("search_runner.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

FAKE_WORKER = r'''
import json, os, sys, time
scenario, log = sys.argv[1:3]
mode, state, offsets, target, start, count, batch, seconds, device, threads = sys.argv[3:]
start, count, batch = int(start), int(count), int(batch)
with open(log, "a") as output:
    output.write(json.dumps({"state":state,"offsets":offsets,"start":start,"count":count,"pid":os.getpid()})+"\n")
def emit(value):
    print(json.dumps(value), flush=True)
emit({"type":"device", "name":"fake"})
if scenario == "exit_error":
    sys.stderr.write("FAKE CUDA ERROR\n")
    sys.exit(3)
if scenario == "stderr_flood":
    sys.stderr.write("X" * 262144 + "STDERR TAIL\n")
    sys.exit(3)
if scenario == "error":
    emit({"type":"error", "message":"hit buffer overflow"})
    sys.exit(4)
if scenario == "partial":
    sys.stdout.write('{"type":"batch"')
    sys.stdout.flush()
    sys.exit(0)
if scenario == "missing_summary":
    sys.exit(0)
if scenario == "no_progress":
    emit({"type":"summary","start":start,"next_candidate":start,"tested":0,"completed":False,"stop_reason":"max_seconds"})
    sys.exit(0)
current, end = start, start + count
while current < end:
    checked = min(batch, end-current)
    hits = []
    if scenario in ("hit", "hang", "boundary"):
        hits = [current]
    if scenario == "two_hits":
        hits = [current,current+1]
    if scenario == "duplicate_hits":
        hits = [current,current]
    record = {"type":"batch","start":current,"count":checked,"elapsed_seconds":0.001,"hits":hits,"overflow":False}
    if scenario == "gap": record["start"] += 1
    if scenario == "short_batch": record["count"] -= 1
    if scenario == "overflow": record["overflow"] = True
    if scenario == "out_of_range_hit": record["hits"] = [current+checked]
    emit(record)
    current += checked
    if scenario == "hang": time.sleep(120)
    if scenario == "segment": break
complete = current == end
emit({"type":"summary","start":start,"next_candidate":current,"tested":current-start+(scenario=="bad_summary"),"elapsed_seconds":0.001,"rate":1000,"completed":complete,"stop_reason":"completed" if complete else "max_seconds"})
'''


class SearchRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.worker = self.directory / "fake.py"
        self.worker.write_text(FAKE_WORKER)
        self.log = self.directory / "calls.jsonl"
        self.checkpoint = self.directory / "checkpoint.json"
        self.state = bytes(range(64))

    def tearDown(self):
        self.temporary.cleanup()

    def search(self, scenario="normal", *, offsets=(63,), state=None, target=b"abcd", callback=None, **kwargs):
        return runner.run_search(
            [sys.executable, "-u", str(self.worker), scenario, str(self.log)],
            self.state if state is None else state, offsets, target, self.checkpoint,
            batch_count=kwargs.pop("batch_count", 64), segment_seconds=kwargs.pop("segment_seconds", 0.1),
            status_callback=callback, **kwargs,
        )

    def document(self):
        return json.loads(self.checkpoint.read_text())

    def seed(self, position, offsets):
        generator = self.search("hit", offsets=offsets)
        next(generator)
        generator.close()
        document = self.document()
        document["next_candidate"] = position
        self.checkpoint.write_text(json.dumps(document))
        self.log.write_text("")

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_complete_and_status_walltime(self):
        events = []
        self.assertEqual(list(self.search(callback=events.append)), [])
        self.assertEqual(self.document()["next_candidate"], 256)
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[-1]["event"], "complete")
        self.assertEqual(events[-1]["tested_this_run"], 256)
        self.assertGreater(events[-1]["elapsed_seconds"], 0)
        self.assertGreater(events[-1]["rate"], 0)
        self.assertEqual(os.stat(self.checkpoint).st_mode & 0o777, 0o600)

    def test_segment_resume_is_contiguous(self):
        events = []
        list(self.search("segment", callback=events.append))
        self.assertEqual([call["start"] for call in self.calls()], [0,64,128,192])
        self.assertEqual(self.document()["next_candidate"], 256)
        self.assertEqual(sum(event["event"] == "segment_complete" for event in events), 4)

    def test_close_does_not_advance_unconsumed_hit(self):
        generator = self.search("hit")
        self.assertEqual(next(generator), 0)
        self.assertEqual(self.document()["next_candidate"], 0)
        generator.close()
        self.assertEqual(self.document()["next_candidate"], 0)

    def test_close_after_last_yield_keeps_batch_for_replay(self):
        generator = self.search("two_hits")
        self.assertEqual(next(generator), 0)
        self.assertEqual(next(generator), 1)
        generator.close()
        self.assertEqual(self.document()["next_candidate"], 0)

    def test_resume_after_consumed_batch(self):
        generator = self.search("hit")
        self.assertEqual(next(generator), 0)
        self.assertEqual(next(generator), 64)
        generator.close()
        self.assertEqual(self.document()["next_candidate"], 64)
        list(self.search())
        self.assertEqual(self.calls()[-1]["start"], 64)
        self.assertEqual(self.document()["next_candidate"], 256)

    def test_zero_offsets_preserves_state_and_maps_zero(self):
        state = bytes([255]) + self.state[1:]
        generator = self.search("hit", offsets=(), state=state)
        self.assertEqual(next(generator), 0)
        with self.assertRaises(StopIteration):
            next(generator)
        self.assertEqual(self.calls()[0]["start"], 255)
        self.assertEqual(self.calls()[0]["count"], 1)
        self.assertEqual(self.calls()[0]["state"], state.hex())
        self.assertEqual(self.document()["next_candidate"], 1)

    def test_six_bytes_cross_shard_boundary(self):
        offsets = (63,0,31,17,42,9)
        self.seed((1 << 40)-1, offsets)
        generator = self.search("boundary", offsets=offsets)
        self.assertEqual(next(generator), (1 << 40)-1)
        self.assertEqual(next(generator), 1 << 40)
        generator.close()
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual([call["start"] for call in calls], [(1<<40)-1,0])
        self.assertEqual(bytes.fromhex(calls[0]["state"])[9], 0)
        self.assertEqual(bytes.fromhex(calls[1]["state"])[9], 1)
        self.assertEqual(calls[0]["offsets"], "63,0,31,17,42")
        self.assertEqual(self.document()["next_candidate"], 1<<40)

    def test_maximum_48_bit_candidate(self):
        offsets = (0,1,2,3,4,5)
        self.seed((1 << 48)-1, offsets)
        self.assertEqual(list(self.search("boundary", offsets=offsets)), [(1 << 48)-1])
        self.assertEqual(self.document()["next_candidate"], 1 << 48)
        self.assertEqual(bytes.fromhex(self.calls()[0]["state"])[5], 255)

    def test_maximum_40_bit_candidate(self):
        offsets = (59,60,61,62,63)
        self.seed((1 << 40)-1, offsets)
        self.assertEqual(list(self.search("boundary", offsets=offsets)), [(1 << 40)-1])
        self.assertEqual(self.document()["next_candidate"], 1 << 40)

    def test_complete_checkpoint_does_not_launch_worker(self):
        list(self.search())
        before = self.log.read_text()
        self.assertEqual(list(self.search()), [])
        self.assertEqual(self.log.read_text(), before)

    def test_config_mismatch_rejected(self):
        generator = self.search("hit")
        next(generator)
        generator.close()
        for kwargs in ({"state":bytes(64)}, {"offsets":(62,)}, {"target":b"different"}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(runner.SearchError, "другой конфигурации"):
                list(self.search(**kwargs))
        self.assertEqual(self.document()["next_candidate"], 0)

    def test_gap_overflow_and_bad_hits_leave_checkpoint(self):
        for scenario in ("gap", "short_batch", "overflow", "duplicate_hits", "out_of_range_hit", "error"):
            with self.subTest(scenario=scenario), self.assertRaises(runner.SearchError):
                list(self.search(scenario))
            self.assertEqual(self.document()["next_candidate"], 0)

    def test_errors_capture_stderr_and_drain_large_output(self):
        for scenario, tail in (("exit_error","FAKE CUDA ERROR"),("stderr_flood","STDERR TAIL")):
            with self.subTest(scenario=scenario), self.assertRaisesRegex(runner.SearchError, tail):
                list(self.search(scenario))
            self.assertEqual(self.document()["next_candidate"], 0)

    def test_partial_missing_summary_and_no_progress(self):
        for scenario in ("partial", "missing_summary", "no_progress"):
            with self.subTest(scenario=scenario), self.assertRaises(runner.SearchError):
                list(self.search(scenario))
            self.assertEqual(self.document()["next_candidate"], 0)

    def test_wrong_summary_does_not_forge_additional_coverage(self):
        with self.assertRaises(runner.SearchError):
            list(self.search("bad_summary"))
        self.assertEqual(self.document()["next_candidate"], 256)

    def test_close_terminates_child_promptly(self):
        generator = self.search("hang")
        next(generator)
        pid = self.calls()[0]["pid"]
        started = time.monotonic()
        generator.close()
        self.assertLess(time.monotonic()-started, 5)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertEqual(self.document()["next_candidate"], 0)

    def test_consumer_validation_time_does_not_trigger_worker_timeout(self):
        command = [sys.executable, "-u", str(self.worker), "normal", str(self.log),
                   "search", self.state.hex(), "63", "abcd", "0", "1", "1", "0.1", "0", "256"]
        real_clock = time.monotonic
        elapsed = [0.0]
        with mock.patch.object(runner.time, "monotonic", side_effect=lambda: real_clock() + elapsed[0]):
            events = runner._worker_events(command, 30)
            self.assertEqual(next(events)[0], "record")
            elapsed[0] = 100.0
            remaining = list(events)
        self.assertEqual(remaining[-1], ("exit", {"returncode":0,"stderr":""}))

    def test_concurrent_use_is_rejected(self):
        first = self.search("hang")
        next(first)
        try:
            with self.assertRaisesRegex(runner.SearchError, "уже используется"):
                list(self.search())
        finally:
            first.close()

    def test_corrupted_checkpoint_rejected(self):
        self.checkpoint.write_text("not JSON")
        with self.assertRaisesRegex(runner.SearchError, "Повреждённый"):
            list(self.search())

    def test_out_of_range_checkpoint_rejected(self):
        self.seed(0, (63,))
        document = self.document()
        document["next_candidate"] = 257
        self.checkpoint.write_text(json.dumps(document))
        with self.assertRaisesRegex(runner.SearchError, "вне диапазона"):
            list(self.search())

    def test_invalid_inputs_do_not_launch_worker(self):
        cases = [
            {"offsets":tuple(range(7))}, {"offsets":(0,0)}, {"offsets":(-1,)},
            {"offsets":(64,)}, {"offsets":(True,)}, {"offsets":[0]},
            {"state":bytes(63)}, {"target":b""}, {"target":bytes(65)},
            {"batch_count":0}, {"batch_count":2**32}, {"threads":0}, {"threads":33},
            {"segment_seconds":0}, {"segment_seconds":float("nan")}, {"segment_seconds":float("inf")},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                list(self.search(**kwargs))
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
