"""Scale the refusal controls to match the rest of the 200-CVE evaluation.

The main run asks 400 answerable questions and 5 control questions. Every
other measure was scaled twenty-five-fold from the pilot and this one was not,
which leaves the refusal row underpowered -- Table II marks it "n.s." at n=5 --
and it is the row the deterministic-refusal claim rests on.

Controls need no corpus curation. A control is any CVE identifier the corpus
does not contain, asked as though it did. This draws them from CISA's Known
Exploited Vulnerabilities catalogue, already cached under
`backend/data/enrichment/cisa_kev.json`, filtered to identifiers absent from
`sample_nvd_200.json`. KEV is the right source rather than a random sample of
NVD: these are the most widely documented vulnerabilities in existence, so
they are the ones a model is most likely to be able to describe from
parametric memory. A refusal control drawn from KEV is therefore a harder test
than one drawn at random, not an easier one.

The five original controls are kept and carried first, so the published 5/5
remains directly comparable to whatever the larger set shows.

    python scripts/run_controls_200.py --condition sharded
    python scripts/run_controls_200.py --condition full

Writes `eval_200_controls_<condition>.json` and checkpoints per question, so
an interrupted run resumes rather than restarting.
"""
import argparse
import json
import os
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = ROOT / "backend" / "data"
CORPUS_200 = DATA / "sample_nvd_200.json"
KEV = DATA / "enrichment" / "cisa_kev.json"

# Must be set before backend.config is imported.
os.environ["CHROMA_PERSIST_DIR"] = str(DATA / "chroma_200")
os.environ["CHROMA_COLLECTION"] = "cve_knowledge_200"
os.environ.setdefault("VECTOR_STORE_PATH", str(DATA / "chroma_200"))

sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

#: Fixed so the control set is the same on every rerun and every machine.
SEED = 20260827


def build_controls(count):
    """`count` KEV identifiers absent from the 200-CVE corpus, year-balanced.

    Sampling evenly across publication years rather than uniformly at random
    matters: KEV is dominated by recent additions, and a set drawn uniformly
    would be almost entirely CVEs published after most models' training
    cutoffs -- which is the easy case for refusal, because the model has
    nothing to recall. Spreading across years keeps the older, famous entries
    that a model plausibly does know.
    """
    with open(CORPUS_200, encoding="utf-8") as handle:
        present = {e.get("cve_id", "").upper()
                   for e in json.load(handle)}
    with open(KEV, encoding="utf-8") as handle:
        catalogue = json.load(handle)["vulnerabilities"]

    by_year = {}
    for entry in catalogue:
        cve = entry.get("cveID", "").upper()
        if not cve.startswith("CVE-") or cve in present:
            continue
        year = cve.split("-")[1]
        by_year.setdefault(year, []).append(entry)

    rng = random.Random(SEED)
    for entries in by_year.values():
        entries.sort(key=lambda e: e["cveID"])       # deterministic input order
        rng.shuffle(entries)

    picked, years = [], sorted(by_year, reverse=True)
    while len(picked) < count and any(by_year[y] for y in years):
        for year in years:
            if by_year[year] and len(picked) < count:
                picked.append(by_year[year].pop())

    controls = []
    for entry in picked:
        name = (entry.get("vulnerabilityName") or "").strip()
        vendor = (entry.get("vendorProject") or "").strip()
        label = name or ("%s vulnerability" % vendor)
        controls.append((entry["cveID"].upper(), label))
    return controls


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--condition", default="sharded",
                        choices=["sharded", "full"])
    parser.add_argument("--count", type=int, default=50,
                        help="KEV controls to add to the original five")
    parser.add_argument("--top-k", type=int, default=6)
    parser.add_argument("--output", default=None)
    parser.add_argument("--checkpoint",
                        default=str(DATA / "eval_200_controls_checkpoint.json"))
    args = parser.parse_args()

    out = args.output or str(DATA / ("eval_200_controls_%s.json" % args.condition))

    from run_eval_200 import seed, make_resumable
    seed(CORPUS_200)

    import run_eval
    run_eval.CORPUS_PATH = CORPUS_200
    run_eval.run_condition = make_resumable(run_eval.run_condition,
                                            args.checkpoint)

    extra = build_controls(args.count)
    keep = {cve for cve, _ in run_eval.CONTROL_CVES}
    run_eval.CONTROL_CVES = (list(run_eval.CONTROL_CVES)
                             + [c for c in extra if c[0] not in keep])

    # Controls only: the answerable half of the question set is what the main
    # run already measured, and re-running it here would spend quota on
    # numbers that already exist.
    run_eval.build_question_set = lambda *a, **k: []

    print("controls: %d (%d original + %d from KEV)"
          % (len(run_eval.CONTROL_CVES), len(keep),
             len(run_eval.CONTROL_CVES) - len(keep)))
    print("condition: %s" % args.condition)
    print("output   : %s" % out)

    argv = ["run_eval",
            "--condition", args.condition,
            "--top-k", str(args.top_k),
            "--output", out]
    sys.argv = argv
    run_eval.main()


if __name__ == "__main__":
    main()
