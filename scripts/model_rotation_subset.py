"""Does the provider's model substitution explain the quality result?

Section VII of the paper concedes that VulnShard's answers were not all written
by the same model -- providers rotate across their catalogues when throttled --
and therefore declines to attribute the quality numbers in Table II to the
reading strategy alone. The abstract nonetheless states the quality-equivalence
claim without that qualification. This script settles which of the two is
right, using only the records already on disk. No API calls are made.

`llm_model` on a sharded record is the model that ran the *reduce* step, i.e.
the model that actually wrote the answer, so it is the right thing to stratify
on. Two questions are asked of it:

  1. Does answer quality differ across the models that served VulnShard?
     If it does not, the substitution is not a confound worth hedging over.
  2. Restricted to the single largest same-model stratum, does the paired
     VulnShard-vs-full-context comparison still hold?

Note on the full-context arm: it is served by an ensemble of three or four
providers on every query and its `llm_model` is a concatenation, so the two
arms were never model-matched and cannot be. What can be controlled is the
substitution on the VulnShard side, which is what Section VII actually names.

    python scripts/model_rotation_subset.py
"""
import io
import json
import os
import statistics
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "backend"))

from services.evaluators import EvaluatorService, _fold  # noqa: E402
import re  # noqa: E402

_CITE = re.compile(r"[\[【]\s*Doc\s*\d+\s*[\]】]", re.IGNORECASE)

DATA = os.path.join(ROOT, "backend", "data")
E = EvaluatorService()


def load(name, key):
    with io.open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return json.load(fh)["records"][key]


S = {r["id"]: r for r in load("eval_200_sharded.json", "sharded")}
F = {r["id"]: r for r in load("eval_200_full.json", "full")}
IDS = sorted(set(S) & set(F))
ANS = [i for i in IDS if S[i]["answerable"]]


def peak(r):
    """Broadcast records leave peak_provider_tokens unset; see README."""
    return r["peak_provider_tokens"] or (r["prompt_tokens"] + r["completion_tokens"])


def rouge(r):
    res = E.evaluate_rouge(r["answer"] or "", r["reference"] or "")
    return res.score if res and res.score is not None else None


def cited(r):
    """The paper's citation-rate test, not a proxy for it.

    evaluate_groundedness counts an answer as citing if it carries any
    [Doc N] or full-width Doc N bracket, after folding dash variants.
    Reimplemented here so the subset uses the same rule as Table II.
    """
    return 1.0 if _CITE.search(_fold(r["answer"] or "")) else 0.0


def mean(xs):
    xs = [x for x in xs if x is not None]
    return statistics.mean(xs) if xs else float("nan")


def support(rs, non_vacuous=False):
    vals = []
    for r in rs:
        if non_vacuous and not r.get("verified_claims"):
            continue
        vals.append(r.get("verified_support_rate", 0.0))
    return mean(vals)


def fabricated(rs):
    return sum(1 for r in rs if r.get("unsupported_cves"))


# ---------------------------------------------------------------- question 1
print("=" * 72)
print("1. VulnShard answer quality, stratified by the model that wrote it")
print("=" * 72)
by_model = defaultdict(list)
for i in ANS:
    by_model[S[i]["llm_model"] or "(none: structural refusal)"].append(S[i])

print("%-34s %5s %8s %8s %8s %6s" %
      ("reduce model", "n", "support", "cite", "ROUGE", "fabr"))
for m, rs in sorted(by_model.items(), key=lambda kv: -len(kv[1])):
    print("%-34s %5d %8.4f %8.4f %8.4f %6d" %
          (m[:34], len(rs), support(rs), mean([cited(r) for r in rs]),
           mean([rouge(r) for r in rs]), fabricated(rs)))

modal = max(by_model, key=lambda m: len(by_model[m]))
print("\nmodal stratum: %s (n=%d)" % (modal, len(by_model[modal])))

others = [r for m, rs in by_model.items() if m != modal for r in rs]
print("everything else pooled       (n=%d) support %.4f  cite %.4f  ROUGE %.4f"
      % (len(others), support(others), mean([cited(r) for r in others]),
         mean([rouge(r) for r in others])))
print("modal minus pooled-others:   support %+.4f  cite %+.4f  ROUGE %+.4f"
      % (support(by_model[modal]) - support(others),
         mean([cited(r) for r in by_model[modal]]) - mean([cited(r) for r in others]),
         mean([rouge(r) for r in by_model[modal]]) - mean([rouge(r) for r in others])))

# ---------------------------------------------------------------- question 2
print("\n" + "=" * 72)
print("2. Paired comparison on the single same-model stratum")
print("=" * 72)
clean = [i for i in ANS if S[i]["llm_model"] == modal]
print("VulnShard answers written by %s: %d of %d answerable\n"
      % (modal, len(clean), len(ANS)))

rows = [
    ("Grounding support",
     support([F[i] for i in clean]), support([S[i] for i in clean])),
    ("Grounding support, non-vacuous",
     support([F[i] for i in clean], True), support([S[i] for i in clean], True)),
    ("Citation rate",
     mean([cited(F[i]) for i in clean]), mean([cited(S[i]) for i in clean])),
    ("Mean ROUGE",
     mean([rouge(F[i]) for i in clean]), mean([rouge(S[i]) for i in clean])),
    ("Peak tokens/provider",
     mean([peak(F[i]) for i in clean]), mean([peak(S[i]) for i in clean])),
    ("Median gen. latency (s)",
     statistics.median([F[i]["generation_ms"] / 1000 for i in clean]),
     statistics.median([S[i]["generation_ms"] / 1000 for i in clean])),
]
print("%-32s %12s %12s %12s" % ("Metric", "Full context", "VulnShard", "delta"))
for label, f, s in rows:
    print("%-32s %12.4f %12.4f %12.4f" % (label, f, s, s - f))

print("\nFabricated CVE IDs      full %d   VulnShard %d"
      % (fabricated([F[i] for i in clean]), fabricated([S[i] for i in clean])))
below = sum(1 for i in clean if peak(S[i]) < peak(F[i]))
print("Peak-token pairs below the diagonal: %d of %d" % (below, len(clean)))
print("Peak-load reduction on this subset:  %.1fx"
      % (mean([peak(F[i]) for i in clean]) / mean([peak(S[i]) for i in clean])))

# --------------------------------------------- how often each path fired
print("\n" + "=" * 72)
print("3. Which refusals went through the structural-skip path")
print("=" * 72)
ctrl = [i for i in IDS if not S[i]["answerable"]]
struct = [i for i in IDS if S[i]["llm_provider"] == "map_reduce(no_evidence)"]
print("control questions:               %d" % len(ctrl))
print("  of those, structural-skip:     %d"
      % sum(1 for i in ctrl if i in struct))
print("  of those, model-mediated:      %d"
      % sum(1 for i in ctrl if i not in struct))
print("structural-skip fired on:        %d queries, all answerable=%s"
      % (len(struct), sorted({S[i]["answerable"] for i in struct})))
print()
print("4. Reconciling Section VII's '130 of 405'")
print("-" * 72)
sub = [i for i in ANS if S[i]["llm_model"] and S[i]["llm_model"] != modal]
nomodel = [i for i in ANS if not S[i]["llm_model"]]
print("  answerable answers by the modal model:      %d" % len(clean))
print("  answerable answers by some other model:     %d" % len(sub))
print("  answerable answers by no model at all:      %d" % len(nomodel))
print("  -> not written by the modal model:          %d of %d"
      % (len(sub) + len(nomodel), len(ANS)))
