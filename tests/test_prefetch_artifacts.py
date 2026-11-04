import json
import unittest

from corrobora.prefetch_artifacts import parse_pecmd_jsonl


BASE = {
    "SourceFilename": "C:\\Windows\\Prefetch\\CALC.EXE-12345678.pf",
    "SourceCreated": "2026-01-01T00:00:00+00:00",
    "SourceModified": "2026-01-02T00:00:00+00:00",
    "SourceAccessed": "2026-01-03T00:00:00+00:00",
    "ExecutableName": "CALC.EXE",
    "Hash": "12345678",
    "Size": "12345",
    "Version": "Windows 10",
    "RunCount": "8",
    "LastRun": "2026-09-01 01:02:03.1234567+02:00",
    "PreviousRun0": "2026-08-01 01:02:03.0000001+00:00",
    "PreviousRun1": "2026-07-01 01:02:03.0000002+00:00",
    "PreviousRun2": "2026-06-01 01:02:03.0000003+00:00",
    "PreviousRun3": "2026-05-01 01:02:03.0000004+00:00",
    "PreviousRun4": "2026-04-01 01:02:03.0000005+00:00",
    "PreviousRun5": "2026-03-01 01:02:03.0000006+00:00",
    "PreviousRun6": "2026-02-01 01:02:03.0000007+00:00",
    "Volume0Name": "C:", "Volume0Serial": "ABC", "Volume0Created": "",
    "Volume1Name": "", "Volume1Serial": "", "Volume1Created": "",
    "Directories": "C:\\Windows", "FilesLoaded": "", "Note": "", "ParsingError": False,
}
CONTEXT = dict(source_name="export.jsonl", source_sha256="a" * 64, host="HOST-1",
               observed_at="2026-10-01T12:00:00-05:00", collector={"name": "PECmd", "version": "1.5.0"})


def encode(record):
    return (json.dumps(record, separators=(",", ":")) + "\n").encode()


class PecmdJsonlTests(unittest.TestCase):
    def test_official_shaped_record_expands_seven_fraction_precision_and_provenance(self):
        observations, warnings = parse_pecmd_jsonl(encode(BASE), **CONTEXT)
        self.assertEqual(warnings, [])
        self.assertEqual(len(observations), 8)
        self.assertEqual(observations[0]["timestamp"], "2026-08-31T23:02:03.123456+00:00")
        self.assertEqual(observations[0]["timestamp_raw"], BASE["LastRun"])
        self.assertEqual(observations[0]["time_semantics"], "prefetch_recorded_run")
        self.assertEqual(observations[0]["source_record"], 1)
        self.assertEqual(observations[0]["native_locator"], {
            "SourceFilename": BASE["SourceFilename"], "lineNumber": 1, "runField": "LastRun"})
        self.assertEqual(observations[0]["details"]["run_count"], 8)
        self.assertEqual(observations[0]["details"]["prefetch_hash"], "12345678")
        self.assertEqual(observations[0]["observed_at"], "2026-10-01T17:00:00+00:00")

    def test_parsing_error_is_retained_with_partial_warning(self):
        record = {**BASE, "ParsingError": True}
        observations, warnings = parse_pecmd_jsonl(encode(record), **CONTEXT)
        self.assertEqual(len(observations), 8)
        self.assertEqual(warnings, ["PECmd partially parsed record at line 1"])

    def test_native_space_separator_z_offset_and_seven_fraction_digits(self):
        record = {**BASE, "RunCount": "1", "LastRun": "2026-09-01 01:02:03.1234567Z",
                  **{f"PreviousRun{i}": "" for i in range(7)}}
        observations, warnings = parse_pecmd_jsonl(encode(record), **CONTEXT)
        self.assertEqual(warnings, [])
        self.assertEqual(observations[0]["timestamp"], "2026-09-01T01:02:03.123456+00:00")
        self.assertEqual(observations[0]["timestamp_raw"], record["LastRun"])

    def test_rejects_fraction_over_seven_digits_and_malformed_offset(self):
        for timestamp in ("2026-09-01 01:02:03.12345678Z", "2026-09-01T01:02:03.1+0000"):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(ValueError, "timestamp"):
                parse_pecmd_jsonl(encode({**BASE, "LastRun": timestamp}), **CONTEXT)

    def test_partial_positive_run_count_without_timestamp_retains_metadata(self):
        record = {**BASE, "ParsingError": True,
                  **{field: "" for field in ("LastRun", *(f"PreviousRun{i}" for i in range(7)))}}
        observations, warnings = parse_pecmd_jsonl(encode(record), **CONTEXT)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["kind"], "prefetch_record")
        self.assertEqual(observations[0]["time_semantics"], "artifact_metadata")
        self.assertEqual(warnings, ["PECmd partially parsed record at line 1"])

    def test_zero_runs_without_timestamps_is_artifact_metadata(self):
        record = {**BASE, "RunCount": "0", **{field: "" for field in ("LastRun", *(f"PreviousRun{i}" for i in range(7)))}}
        observations, _ = parse_pecmd_jsonl(encode(record), **CONTEXT)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["kind"], "prefetch_record")
        self.assertIsNone(observations[0]["timestamp"])

    def test_distinct_source_hashes_change_observation_identity(self):
        one, _ = parse_pecmd_jsonl(encode({**BASE, "RunCount": "1", **{f"PreviousRun{i}": "" for i in range(7)}}), **CONTEXT)
        two, _ = parse_pecmd_jsonl(encode({**BASE, "RunCount": "1", **{f"PreviousRun{i}": "" for i in range(7)}}), **{**CONTEXT, "source_sha256": "b" * 64})
        self.assertNotEqual(one[0]["id"], two[0]["id"])

    def test_rejects_duplicate_keys_nested_values_naive_time_and_bad_types(self):
        cases = [
            (b'{"SourceFilename":"a","SourceFilename":"b"}\n', "duplicate"),
            (encode({**BASE, "Extra": {"nested": True}}), "nested"),
            (encode({**BASE, "LastRun": "2026-01-01 00:00:00"}), "timestamp"),
            (encode({**BASE, "ParsingError": "false"}), "field type"),
        ]
        for content, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                parse_pecmd_jsonl(content, **CONTEXT)

    def test_requires_declared_exporter_version_and_rejects_oversized_line(self):
        with self.assertRaisesRegex(ValueError, "exporter"):
            parse_pecmd_jsonl(encode(BASE), **{**CONTEXT, "collector": {"name": "PECmd", "version": " "}})
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            parse_pecmd_jsonl(b'{"x":"' + b'a' * (64 * 1024) + b'"}\n', **CONTEXT)


if __name__ == "__main__":
    unittest.main()
