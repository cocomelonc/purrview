import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("purr_agent", ROOT / "tools" / "purr_agent.py")
AGENT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
# Register before exec so @dataclass can resolve the module during class build.
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SCRATCH = ROOT / "build" / "agent" / "_test"


def _ctx():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return AGENT.RunContext(live=False, serial=None, output_dir=SCRATCH)


class RegistryTests(unittest.TestCase):
    def test_every_method_covers_the_required_metadata(self):
        for method_id, method in AGENT.REGISTRY.items():
            self.assertIn(method.area, AGENT.AREAS)
            self.assertTrue(method.prerequisites)
            self.assertGreater(method.cost_s, 0)
            self.assertGreater(method.timeout_s, 0)
            self.assertTrue(method.evidence_type)
            self.assertIn(method.risk, ("low", "medium"))
            self.assertTrue(method.success)      # success criterion
            self.assertTrue(method.uncertainty)  # uncertainty criterion

    def test_all_three_areas_are_represented(self):
        covered = {m.area for m in AGENT.REGISTRY.values()}
        self.assertEqual(covered, set(AGENT.AREAS))


class AllowListTests(unittest.TestCase):
    def test_bogus_method_id_is_rejected(self):
        with self.assertRaises(AGENT.PlanError):
            AGENT.validate_plan(
                {"select": [{"area": "aslr", "method_id": "rm -rf /"}]},
                ["aslr"], set(), "model", None,
            )

    def test_method_from_a_closed_area_is_rejected(self):
        with self.assertRaises(AGENT.PlanError):
            AGENT.validate_plan(
                {"select": [{"area": "rw", "method_id": "repeatability"}]},
                ["aslr"], set(), "model", None,
            )

    def test_already_run_method_is_rejected(self):
        with self.assertRaises(AGENT.PlanError):
            AGENT.validate_plan(
                {"select": [{"area": "aslr", "method_id": "maps_vs_dladdr"}]},
                ["aslr"], {"maps_vs_dladdr"}, "model", None,
            )

    def test_out_of_list_params_fall_back_to_default(self):
        method = AGENT.REGISTRY["crash_reproducibility"]
        self.assertEqual(method.coerce_params({"trials": 999})["trials"], 3)
        self.assertEqual(method.coerce_params({"trials": 5})["trials"], 5)

    def test_confidence_is_clamped_to_unit_range(self):
        plan = AGENT.validate_plan(
            {"select": [{"area": "aslr", "method_id": "maps_vs_dladdr"}], "confidence": 9},
            ["aslr"], set(), "model", "m",
        )
        self.assertEqual(plan.confidence, 1.0)


class EvidenceTests(unittest.TestCase):
    def test_simulated_canary_readback_discloses_the_known_secret(self):
        ev = AGENT.method_canary_readback(_ctx(), {})
        self.assertEqual(ev.status, "conclusive")
        self.assertTrue(ev.observed["matched"])
        self.assertEqual(ev.observed["disclosed"], "meow-meow MCTTP 2026")

    def test_rw_window_past_companion_buffer_is_refused(self):
        ev = AGENT.method_bounded_memory_canary(
            _ctx(), {"offset": 60, "length": 16})
        self.assertEqual(ev.verdict, "refuted")
        self.assertFalse(ev.observed["in_bounds"])

    def test_offset_length_boundary_pins_the_companion_size(self):
        ev = AGENT.method_offset_length_boundary(_ctx(), {})
        self.assertEqual(ev.status, "conclusive")
        self.assertEqual(ev.observed["enforced_size"], AGENT.RW_COMPANION_SIZE)

    def test_crash_artifact_correlation_stays_inconclusive(self):
        ev = AGENT.method_crash_artifact_correlation(_ctx(), {})
        self.assertEqual(ev.status, "inconclusive")


class LoopTests(unittest.TestCase):
    def test_inconclusive_first_method_keeps_the_area_open(self):
        ctx = _ctx()
        evidence = [AGENT.REGISTRY["crash_artifact_correlation"].run(ctx, {})]
        self.assertEqual(AGENT.area_verdict("aslr", evidence)["status"], "inconclusive")

        # The next round must be able to select a stronger, still-unrun method.
        plan = AGENT.deterministic_plan(["aslr"], {"crash_artifact_correlation"}, evidence)
        self.assertTrue(plan.select)
        evidence.append(AGENT.REGISTRY[plan.select[0].method_id].run(ctx, plan.select[0].params))
        self.assertEqual(AGENT.area_verdict("aslr", evidence)["status"], "conclusive")

    def test_deterministic_planner_confirms_all_areas(self):
        ctx = _ctx()
        evidence, done, open_areas = [], set(), list(AGENT.AREAS)
        for _ in range(6):
            if not open_areas:
                break
            plan = AGENT.deterministic_plan(open_areas, done, evidence)
            for sel in plan.select:
                evidence.append(AGENT.REGISTRY[sel.method_id].run(ctx, sel.params))
                done.add(sel.method_id)
            open_areas = [a for a in open_areas
                          if AGENT.area_verdict(a, evidence)["status"] != "conclusive"]
        self.assertEqual(open_areas, [])
        for area in AGENT.AREAS:
            self.assertEqual(AGENT.area_verdict(area, evidence)["verdict"], "confirmed")


if __name__ == "__main__":
    unittest.main()
