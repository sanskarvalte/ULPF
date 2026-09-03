"""
Unit tests for ULPF Evaluation Engine (app/evaluation/evaluator.py).
"""

from __future__ import annotations

import unittest
from pathlib import Path

from app.evaluation.evaluator import evaluate_ground_truth, evaluate_log_file


class TestEvaluationEngine(unittest.TestCase):
    def test_evaluate_ground_truth(self):
        result = evaluate_ground_truth()
        self.assertNotIn("error", result)
        self.assertGreater(result["total_test_events"], 0)
        self.assertGreaterEqual(result["format_detection_accuracy_percent"], 90.0)
        self.assertGreaterEqual(result["overall_field_accuracy_percent"], 85.0)

    def test_evaluate_sample_file_completeness(self):
        sample_path = Path(__file__).resolve().parent.parent.parent / "datasets" / "sample_data" / "Linux_2k.log"
        if sample_path.exists():
            result = evaluate_log_file(sample_path)
            self.assertNotIn("error", result)
            self.assertEqual(result["raw_event_count"], result["normalized_event_count"] + result["unparsed_event_count"])
            self.assertEqual(result["duplicate_count"], 0)
            self.assertEqual(result["fan_out_ratio"], 1.0)
            self.assertTrue(result["event_count_integrity_passed"])


if __name__ == "__main__":
    unittest.main()
