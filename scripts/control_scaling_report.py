"""Score the scaled refusal controls, with intervals and by refusal path.

Reads whatever `run_controls_200.py` has written for each arm and reports:

  - correct refusals and hallucinated answers, with Wilson 95% intervals, so
    the row Table II had to mark "n.s." at n=5 can carry a real interval;
  - how many refusals came from the structural skip (no model call at all)
    versus a model that happened to decline, which is the measurement the
    deterministic-refusal claim needs and the 5-control run never produced;
  - the same split for the five original controls alone, so the published
    5/5 stays directly comparable.

    python scripts/control_scaling_report.py
"""
import io
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "backend"))

from services.evaluators import EvaluatorService  # noqa: E402

DATA = os.path.join(ROOT, "backend", "data")
E = EvaluatorService()

ORIGINAL = {"CVE-2019-0708", "CVE-2017-0144", "CVE-2014-0160",
            "CVE-2018-7600", "CVE-2016-5195"}
STRUCTURAL = "map_reduce(no_evidence)"


def wilson(successes, total, z=1.96):
    """Wilson score interval -- the paper's convention for every proportion."""
    if not total:
        return (0.0, 0.0)
    p = successes / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def load(condition):
    path = os.path.join(DATA, "eval_200_controls_%s.json" % condition)
    if not os.path.exists(path):
        return None
    with io.open(path, encoding="utf-8") as fh:
        return json.load(fh)["records"][condition]


def report(condition, records):
    controls = [r for r in records if not r["answerable"]]
    answers = [r["answer"] or "" for r in controls]
    subjects = [r["id"] for r in controls]
    # Subject-scoped: an answer that declines on the absent CVE and then
    # discusses a different, in-corpus one is irrelevant, not fabricated.
    res = E.evaluate_refusal(answers, subjects)
    correct = res.details["correct_refusals"]
    total = res.details["control_questions"]
    lo, hi = wilson(correct, total)

    struct = [r for r in controls if r.get("llm_provider") == STRUCTURAL]
    model_med = [r for r in controls if r.get("llm_provider") != STRUCTURAL]

    print("-" * 66)
    print("%s: %d controls" % (condition, total))
    print("  correct refusals      %3d / %-3d  %.4f [%.2f, %.2f]"
          % (correct, total, correct / total, lo, hi))
    print("  hallucinated answers  %3d" % res.details["hallucinated_answers"])
    print("  refusal path: structural (no model call) %d, model-mediated %d"
          % (len(struct), len(model_med)))

    if struct:
        sa = [r["answer"] or "" for r in struct]
        sc = E.evaluate_refusal(sa, [r["id"] for r in struct]).details[
            "correct_refusals"]
        print("    of the structural ones, scored correct: %d / %d"
              % (sc, len(struct)))
    if model_med:
        ma = [r["answer"] or "" for r in model_med]
        mc = E.evaluate_refusal(ma, [r["id"] for r in model_med]).details[
            "correct_refusals"]
        print("    of the model-mediated ones, scored correct: %d / %d"
              % (mc, len(model_med)))

    orig = [r for r in controls if r["id"] in ORIGINAL]
    if orig:
        oc = E.evaluate_refusal([r["answer"] or "" for r in orig],
                                [r["id"] for r in orig])
        print("  original five only:   %d / %d correct"
              % (oc.details["correct_refusals"], len(orig)))

    bad = [r for r in controls
           if E.evaluate_refusal([r["answer"] or ""], [r["id"]]).details[
               "hallucinated_answers"]]
    for r in bad:
        print("    ANSWERED: %s | %s | %r"
              % (r["id"], r.get("llm_provider"), (r["answer"] or "")[:90]))
    return correct, total, len(struct)


if __name__ == "__main__":
    seen = False
    for condition in ("sharded", "full"):
        records = load(condition)
        if records is None:
            print("-" * 66)
            print("%s: not run yet" % condition)
            continue
        seen = True
        report(condition, records)
    if not seen:
        raise SystemExit("no control results found; run run_controls_200.py")
