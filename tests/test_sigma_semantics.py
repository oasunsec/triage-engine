import itertools
import tempfile
import unittest
from pathlib import Path

from corrobora.sigma_loader import load_rules
from corrobora.sigma_runner import _parse_condition, _tokenize, evaluate_rules


ROOT = Path(__file__).resolve().parents[1]


class SigmaConditionSemanticsTests(unittest.TestCase):
    def test_boolean_precedence_and_nested_truth_tables(self):
        expressions = {
            "a or b and c": lambda a, b, c: a or (b and c),
            "(a or b) and c": lambda a, b, c: (a or b) and c,
            "(a and b) or c": lambda a, b, c: (a and b) or c,
            "not (a or b) and c": lambda a, b, c: not (a or b) and c,
            "not not a or (b and not c)": lambda a, b, c: a or (b and not c),
        }
        for expression, expected in expressions.items():
            for values_tuple in itertools.product((False, True), repeat=3):
                values = dict(zip(("a", "b", "c"), values_tuple))
                with self.subTest(expression=expression, values=values):
                    self.assertEqual(_parse_condition(_tokenize(expression), values), expected(**values))

    def test_parser_rejects_unconsumed_syntax_and_unknown_selectors(self):
        for expression in ("a & b", "a)", "(a", "a b", "a or", ""):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                _tokenize(expression) if expression == "a & b" or expression == "" else _parse_condition(_tokenize(expression), {"a": True, "b": True})
        with self.assertRaisesRegex(ValueError, "unknown Sigma selector"):
            _parse_condition(_tokenize("missing"), {"a": True})


class SigmaRuleValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp_root = ROOT / "runtime" / "temp" / "sigma-semantics-tests"
        self.temp_root.mkdir(parents=True, exist_ok=True)

    def _load_text(self, text):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as folder:
            path = Path(folder) / "rule.yml"
            path.write_text(text, encoding="utf-8")
            return load_rules([str(path)])

    def test_supported_rule_loads_and_invalid_rules_are_rejected(self):
        supported = """title: supported
detection:
  sel:
    Image|endswith: powershell.exe
    CommandLine|contains: -enc
  condition: sel
"""
        rules, diagnostics = self._load_text(supported)
        self.assertEqual(len(rules), 1)
        self.assertEqual(diagnostics, [])

        invalid_bodies = (
            "condition: missing",
            "condition: sel & sel",
            "condition: (sel",
            "condition: sel)",
        )
        for body in invalid_bodies:
            text = f"""title: invalid
detection:
  sel:
    Image: powershell.exe
  {body}
"""
            with self.subTest(body=body):
                rules, diagnostics = self._load_text(text)
                self.assertEqual(rules, [])
                self.assertTrue(diagnostics)

    def test_loader_rejects_unknown_chained_and_regex_modifiers(self):
        fields = ("Image|wildcard", "Image|contains|regex", "Image|regex", "Image|re")
        for field in fields:
            value = "powershell.exe"
            text = f"""title: invalid field
detection:
  sel:
    '{field}': '{value}'
  condition: sel
"""
            with self.subTest(field=field):
                rules, diagnostics = self._load_text(text)
                self.assertEqual(rules, [])
                self.assertTrue(diagnostics)

    def test_direct_dictionary_rules_receive_same_validation(self):
        rules = [{
            "title": "bad direct rule",
            "detection": {
                "sel": {"Image|unknown": "x"},
                "condition": "sel",
            },
        }]
        alerts, diagnostics = evaluate_rules([], rules)
        self.assertEqual(alerts, [])
        self.assertTrue(any("unsupported Sigma field or modifier" in item for item in diagnostics))


if __name__ == "__main__":
    unittest.main()
