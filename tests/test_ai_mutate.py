import importlib.util
import hashlib
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ai_mutate", ROOT / "tools" / "ai_mutate.py")
AI = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(AI)


class AiMutationTests(unittest.TestCase):
    def test_png_oob_recipe_is_bounded_and_different(self):
        recipe = AI.validate_recipe(AI.fallback_recipe("png", "oob"), "png", "oob")
        data = AI.build_png(recipe)
        baseline = (ROOT / "app/src/main/assets/purrview-oob.png").read_bytes()
        self.assertEqual(AI.expected_outcome(recipe), "OOB_WRITE")
        self.assertLessEqual(len(data), AI.MAX_FIXTURE)
        self.assertNotEqual(hashlib.sha256(data).digest(), hashlib.sha256(baseline).digest())

    def test_pdu_control_and_oob_are_distinct(self):
        control = AI.validate_recipe(AI.fallback_recipe("pdu", "control"), "pdu", "control")
        oob = AI.validate_recipe(AI.fallback_recipe("pdu", "oob"), "pdu", "oob")
        self.assertEqual(AI.expected_outcome(control), "CONTROL")
        self.assertEqual(AI.expected_outcome(oob), "OOB_WRITE")
        self.assertNotEqual(AI.build_pdu(control), AI.build_pdu(oob))

    def test_unknown_or_unsafe_fields_are_rejected(self):
        recipe = AI.fallback_recipe("png", "oob")
        recipe["shellcode"] = "forbidden"
        with self.assertRaises(AI.RecipeError):
            AI.validate_recipe(recipe, "png", "oob")

    def test_offline_cli_writes_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.png"
            self.assertEqual(AI.main(["--offline", "--output", str(output)]), 0)
            self.assertTrue(output.is_file())
            self.assertTrue(output.with_suffix(".png.json").is_file())


if __name__ == "__main__":
    unittest.main()
