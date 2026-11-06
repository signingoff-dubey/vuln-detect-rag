"""Refusal-metric cases taken verbatim from the 55-control run.

Every string here is a real answer produced by the system, not a constructed
example. They were found by hand-reading all 110 control answers after the
metric reported five failures in the full-context arm and one in the sharded
arm -- an asymmetry that turned out to be the metric, not the systems: the
full-context arm writes longer, more discursive refusals, and three of the
metric's patterns mis-scored them.

Keeping them as tests is the point. The metric has now been wrong in both
directions twice, and each time the fix was verified against a handful of
answers that were then thrown away.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.evaluators import EvaluatorService  # noqa: E402


@pytest.fixture
def evaluator():
    return EvaluatorService()


# --- refusals the metric used to score as hallucinations ------------------

REFUSALS = [
    # "is mentioned" was absent from the decline vocabulary, which knew only
    # "does not mention". The answer declined and asserted nothing, and was
    # counted as a hallucination for using the wrong verb form.
    ("CVE-2007-5659",
     "Based on the provided context, neither CVE-2007-5659 nor its CVSS "
     "score is mentioned. Therefore, I cannot provide a description of the "
     "vulnerability or its associated CVSS score."),

    # "is missing" had no entry at all.
    ("CVE-2019-1652",
     "Based on the provided context, the requested information about "
     "CVE-2019-1652 and its details, including any available CVSS score, "
     "is missing."),

    # The negation guard required "not" immediately after the verb, so
    # "is also not available" read as a description while "is not available"
    # did not.
    ("CVE-2023-28461",
     "Based on the provided context documents [Doc 1] to [Doc 6], there is "
     "no information available regarding CVE-2023-28461 or the Array "
     "Networks AG and vxAG ArrayOS vulnerability. The CVSS score for "
     "CVE-2023-28461 is also not available in the documents."),

    # Declines on the subject, then discusses a different CVE that really is
    # in the corpus. Irrelevant, but not a fabrication about the subject.
    ("CVE-2005-2773",
     "Based on the provided context documents, CVE-2022-41983 is a "
     "vulnerability affecting opentext brava! desktop versions not specified "
     "in the context. It allows remote attackers to execute arbitrary code "
     "on affected systems.\n\nThe CVSS score for CVE-2005-2773 is not "
     "available in the provided context documents. Neither is any "
     "information about CVE-2005-2773 or HP OpenView Network Node Manager "
     "available in the given context."),
]


@pytest.mark.parametrize("subject,answer", REFUSALS,
                         ids=[cve for cve, _ in REFUSALS])
def test_genuine_refusals_score_as_refusals(evaluator, subject, answer):
    result = evaluator.evaluate_refusal([answer], [subject])
    assert result.details["correct_refusals"] == 1, result.details


# --- the two answers that really did fail --------------------------------

def test_hedged_then_asserts_about_the_subject(evaluator):
    """Declines, then states a fact about the absent CVE and cites a document
    that cannot contain it. The full-context arm's only control failure."""
    answer = (
        "The provided context documents do not contain information regarding "
        "CVE-2020-9715 or its CVSS score. One source notes that CVE-2020-9715 "
        "is related to a Use-After-Free issue in Adobe Acrobat [Doc 1], while "
        "other sources state that the provided context does not contain "
        "information about this vulnerability [Doc 2, Doc 3].")
    details = evaluator.evaluate_refusal([answer], ["CVE-2020-9715"]).details
    assert details["correct_refusals"] == 0, details
    assert details["hedged_but_answered"] == 1, details


def test_answers_without_naming_the_identifier(evaluator):
    """States attack vector, complexity and privilege requirements for an
    absent CVE without ever naming it, and never declines.

    The sharded arm's only control failure, and the reason the metric cannot
    fall back to "no decline and no identifier means nothing was supplied":
    a test keyed on the identifier is blind to this answer.
    """
    answer = (
        "Exploitation status: This vulnerability is listed on the CISA Known "
        "Exploited Vulnerabilities catalogue.\n\nExploitability: The attack "
        "vector is browser-based, requiring medium attack complexity and "
        "administrative privileges. User interaction is required.")
    details = evaluator.evaluate_refusal([answer], ["CVE-2016-0034"]).details
    assert details["correct_refusals"] == 0, details
    assert details["answered_outright"] == 1, details


def test_subject_scoping_is_optional(evaluator):
    """Callers that pass no subjects keep the old any-identifier behaviour."""
    answer = "CVE-2019-0708 is a remote code execution flaw in Windows RDP."
    assert evaluator.evaluate_refusal([answer]).details[
        "correct_refusals"] == 0
