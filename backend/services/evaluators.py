import math
import re
from collections import Counter
from models.schemas import EvalResult


#: Dash variants some providers emit inside identifiers, folded to ASCII
#: so "CVE‑2021‑38894" matches "CVE-2021-38894".
_DASH_FOLD = {ord(c): "-" for c in "‐‑‒–—−"}


_IDENT = re.compile(r"CVE-\d{4}-\d{4,}|CWE-\d+", re.IGNORECASE)


def _fold(text: str) -> str:
    return (text or "").translate(_DASH_FOLD)


class EvaluatorService:
    """Compute evaluation metrics for RAG and scanner outputs."""

    # ------------------------------------------------------------------
    # Retrieval metrics
    #
    # Generation metrics alone cannot tell you whether a RAG system works: a
    # fluent answer built on the wrong documents scores well on BLEU. These
    # measure the retriever directly, against the document that should have
    # been found.
    # ------------------------------------------------------------------

    def evaluate_retrieval(
        self, retrieved_ids: list[list[str]], expected_ids: list[str]
    ) -> EvalResult:
        """Score retrieval quality across a set of queries.

        Args:
            retrieved_ids: Per query, the CVE IDs retrieved in rank order.
            expected_ids: Per query, the CVE ID that should have been retrieved.

        Returns:
            EvalResult with hit rate, MRR, and mean reciprocal position.
        """
        if not expected_ids:
            return EvalResult(metric="Retrieval", score=0.0,
                              details={"error": "No queries"})

        hits = 0
        reciprocal_ranks = []
        top1_hits = 0

        for retrieved, expected in zip(retrieved_ids, expected_ids):
            normalized = [str(r).upper() for r in retrieved]
            target = str(expected).upper()

            if normalized and normalized[0] == target:
                top1_hits += 1

            if target in normalized:
                hits += 1
                # Rank is 1-based: the reciprocal of the first correct position.
                reciprocal_ranks.append(1.0 / (normalized.index(target) + 1))
            else:
                reciprocal_ranks.append(0.0)

        total = len(expected_ids)
        hit_rate = hits / total
        mrr = sum(reciprocal_ranks) / total

        return EvalResult(
            metric="Retrieval",
            score=round(mrr, 4),
            details={
                "hit_rate_at_k": round(hit_rate, 4),
                "precision_at_1": round(top1_hits / total, 4),
                "mrr": round(mrr, 4),
                "queries": total,
                "hits": hits,
                "misses": total - hits,
            },
        )

    def evaluate_groundedness(
        self, answers: list[str], contexts: list[list[str]]
    ) -> EvalResult:
        """Estimate how well answers are supported by retrieved context.

        Two cheap, deterministic signals, chosen because they need no second
        LLM to act as judge:
          - citation rate: does the answer reference [Doc N] as instructed?
          - CVE fidelity: does every CVE ID in the answer appear in the context?
            An ID that is not in the context was invented.
        """
        if not answers:
            return EvalResult(metric="Groundedness", score=0.0,
                              details={"error": "No answers"})

        cited = 0
        clean = 0
        hallucinated_total = 0

        for answer, context_docs in zip(answers, contexts):
            # Fold dash variants before matching. Some providers render
            # identifiers with non-breaking hyphens (CVE‑2021‑38894),
            # which an ASCII-hyphen pattern silently misses.
            answer = _fold(answer)

            # Accept full-width brackets as well as ASCII. groq's gpt-oss
            # models cite as 【Doc 1】, and counting only "[Doc 1]"
            # undercounts their citations.
            if re.search(r"[\[【]\s*Doc\s*\d+\s*[\]】]", answer,
                         re.IGNORECASE):
                cited += 1

            context_blob = _fold(" ".join(context_docs)).upper()
            answer_cves = set(
                c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", answer, re.IGNORECASE)
            )
            unsupported = {c for c in answer_cves if c not in context_blob}
            hallucinated_total += len(unsupported)
            if not unsupported:
                clean += 1

        total = len(answers)
        fidelity = clean / total

        return EvalResult(
            metric="Groundedness",
            score=round(fidelity, 4),
            details={
                "citation_rate": round(cited / total, 4),
                "cve_fidelity": round(fidelity, 4),
                "answers_with_unsupported_cves": total - clean,
                "unsupported_cve_mentions": hallucinated_total,
                "answers": total,
            },
        )

    #: Ways a model declines. Tolerant of do/does/did and of contain/include/
    #: mention, because "do not contain" and "does not contain" are the same
    #: refusal and an exact-phrase list scored one of them as a hallucination.
    _DECLINE = re.compile(
        r"(?:do(?:es)?|did)\s+not\s+(?:contain|include|have|mention|cover|list|provide)"
        r"|(?:is|are|was|were)\s+(?:\w+\s+){0,2}?not\s+"
        r"(?:mentioned|listed|described|documented|specified|provided|given|"
        r"available|present|found|included|covered)"
        r"|neither\b[^.]{0,120}?\bnor\b"
        r"|no\s+(?:information|entry|entries|matching|relevant|record|data|details)"
        r"|not\s+(?:available|present|found|in\s+the\s+provided|included)"
        r"|(?:is|are)\s+missing"
        r"|lacks?\s+(?:any\s+)?(?:information|details|reference)"
        r"|un(?:available|known)"
        r"|(?:cannot|can't|unable\s+to)\s+(?:find|locate|answer|provide)"
        r"|NOTHING_RELEVANT",
        re.IGNORECASE)

    #: A CVSS score actually stated, as opposed to the phrase "CVSS score"
    #: appearing inside a refusal ("... or its CVSS score").
    _SCORE_STATED = re.compile(
        r"(?:CVSS|base\s+score)[^\d\n]{0,24}(\d{1,2}(?:\.\d)?)", re.IGNORECASE)

    #: The subject being described rather than declined: "CVE-X is a ...",
    #: "CVE-X affects ...". This is what a parametric-memory answer looks like.
    #: The subject being described rather than declined: "CVE-X is a ...".
    #: The negation guard tolerates up to two intervening words, because
    #: "CVE-X is also not available" is a refusal and an immediate-`not`
    #: lookahead read it as a description.
    _DESCRIBES_TAIL = (
        r"\s*(?:\([^)]{0,40}\))?\s*"
        r"(?:is|was|are|were|affects?|allows?|enables?|permits?|exists?)\b"
        r"(?!(?:\s+\w+){0,2}\s+(?:not\b|never\b|un(?:available|known)|"
        r"available|absent|missing|mentioned|listed|documented))")
    _DESCRIBES = re.compile(r"CVE-\d{4}-\d{4,}" + _DESCRIBES_TAIL,
                            re.IGNORECASE)

    def _states_a_score(self, text: str) -> bool:
        """Whether the answer actually asserts a CVSS score.

        CVSS is defined on 0.0-10.0, so a captured value outside that
        range is a parse artefact rather than a claim -- typically a
        year picked out of an identifier, or a grounding caveat the
        pipeline appended about one.
        """
        for raw in self._SCORE_STATED.findall(text):
            try:
                if 0.0 <= float(raw) <= 10.0:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _describes_subject(self, text: str, subject: str | None) -> bool:
        """Does the answer describe the CVE it was asked about?

        Without a subject this asks whether the answer describes *any*
        identifier, which mis-scores an answer that declines on the absent CVE
        and then discusses a different one that really is in the corpus. That
        is an irrelevant answer, not a fabricated one, and the two should not
        share a bucket.
        """
        if not subject:
            return bool(self._DESCRIBES.search(text))
        pattern = re.compile(re.escape(subject) + self._DESCRIBES_TAIL,
                             re.IGNORECASE)
        return bool(pattern.search(text))

    def evaluate_refusal(self, answers: list[str],
                         subjects: list[str] | None = None) -> EvalResult:
        """Measure correct refusal on questions the corpus cannot answer.

        Run against control questions whose subject is deliberately absent from
        the knowledge base. A system that answers these is hallucinating, so a
        high score here is as important as a high score on answerable ones.

        Judged on what the answer supplies, not on whether a phrase appears in
        it. A substring test fails in both directions and did: it scored three
        1,000-character answers about BlueKeep, EternalBlue and Heartbleed as
        correct refusals because each buried a hedge mid-paragraph, and later
        scored four genuine refusals as hallucinations because they said "do
        not contain" rather than "does not contain", or replied with the bare
        marker.

        An answer counts as a refusal when it declines AND does not go on to
        describe the subject or state a score for it.
        """
        if not answers:
            return EvalResult(metric="Refusal", score=0.0,
                              details={"error": "No answers"})

        refused = 0
        hedged_but_answered = 0
        answered_outright = 0
        subject_list = list(subjects or [])
        for index, raw in enumerate(answers):
            text = _fold(raw or "").strip()
            subject = (subject_list[index]
                       if index < len(subject_list) else None)
            declines = bool(self._DECLINE.search(text))
            # Blank out identifiers first: "the CVSS score for
            # CVE-2019-0708 is not given" otherwise matches the CVE's
            # year as though it were a score of 20.
            masked = _IDENT.sub(" CVE-ID ", text)
            asserts = (self._states_a_score(masked)
                       or self._describes_subject(text, subject))
            if declines and not asserts:
                refused += 1
            elif declines and asserts:
                # Hedged and answered anyway -- the failure mode the old
                # substring test could not see.
                hedged_but_answered += 1
            else:
                # No decline in any phrasing this pattern knows. That is not a
                # refusal even when no identifier is named: the one control
                # both arms failed states an attack vector, complexity and
                # privilege requirement for an absent CVE without ever
                # naming it, so a test keyed on the identifier cannot see it
                # and a fall-through to "refused" would swallow it.
                answered_outright += 1

        total = len(answers)
        return EvalResult(
            metric="Refusal",
            score=round(refused / total, 4),
            details={
                "correct_refusals": refused,
                "hallucinated_answers": total - refused,
                "hedged_but_answered": hedged_but_answered,
                "answered_outright": answered_outright,
                "control_questions": total,
            },
        )

    def evaluate_cve_detection(
        self, predicted: list[str], ground_truth: list[str]
    ) -> EvalResult:
        """Compute precision, recall, F1 for CVE detection."""
        pred_set = set(p.upper() for p in predicted)
        truth_set = set(t.upper() for t in ground_truth)

        tp = len(pred_set & truth_set)
        fp = len(pred_set - truth_set)
        fn = len(truth_set - pred_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        detection_rate = tp / len(truth_set) if truth_set else 0.0

        return EvalResult(
            metric="CVE Detection",
            score=round(f1, 4),
            details={
                "detection_rate": round(detection_rate, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
            },
        )

    def evaluate_bleu(self, prediction: str, reference: str) -> EvalResult:
        """Compute BLEU score for RAG answer quality."""
        pred_tokens = self._tokenize(prediction)
        ref_tokens = self._tokenize(reference)

        if not pred_tokens or not ref_tokens:
            return EvalResult(
                metric="BLEU", score=0.0, details={"error": "Empty tokens"}
            )

        # BLEU-1 through BLEU-4
        bleu_scores = []
        for n in range(1, 5):
            pred_ngrams = self._get_ngrams(pred_tokens, n)
            ref_ngrams = self._get_ngrams(ref_tokens, n)

            if not pred_ngrams:
                bleu_scores.append(0.0)
                continue

            clipped = 0
            for ngram, count in pred_ngrams.items():
                clipped += min(count, ref_ngrams.get(ngram, 0))

            precision = clipped / sum(pred_ngrams.values()) if pred_ngrams else 0.0
            bleu_scores.append(precision)

        # Brevity penalty
        bp = min(1.0, len(pred_tokens) / len(ref_tokens)) if ref_tokens else 0.0

        # Geometric mean
        if all(s > 0 for s in bleu_scores):
            geo_mean = math.exp(
                sum(math.log(s) for s in bleu_scores) / len(bleu_scores)
            )
        else:
            geo_mean = 0.0

        bleu = bp * geo_mean

        return EvalResult(
            metric="BLEU",
            score=round(bleu, 4),
            details={
                "bleu_1": round(bleu_scores[0], 4) if len(bleu_scores) > 0 else 0,
                "bleu_2": round(bleu_scores[1], 4) if len(bleu_scores) > 1 else 0,
                "bleu_3": round(bleu_scores[2], 4) if len(bleu_scores) > 2 else 0,
                "bleu_4": round(bleu_scores[3], 4) if len(bleu_scores) > 3 else 0,
                "brevity_penalty": round(bp, 4),
            },
        )

    def evaluate_rouge(self, prediction: str, reference: str) -> EvalResult:
        """Compute ROUGE-1, ROUGE-2, ROUGE-L scores."""
        pred_tokens = self._tokenize(prediction)
        ref_tokens = self._tokenize(reference)

        if not pred_tokens or not ref_tokens:
            return EvalResult(
                metric="ROUGE", score=0.0, details={"error": "Empty tokens"}
            )

        # ROUGE-1
        rouge_1 = self._rouge_n(pred_tokens, ref_tokens, 1)

        # ROUGE-2
        rouge_2 = self._rouge_n(pred_tokens, ref_tokens, 2)

        # ROUGE-L (LCS-based)
        rouge_l = self._rouge_l(pred_tokens, ref_tokens)

        avg_score = (rouge_1["f1"] + rouge_2["f1"] + rouge_l["f1"]) / 3

        return EvalResult(
            metric="ROUGE",
            score=round(avg_score, 4),
            details={
                "rouge_1": rouge_1,
                "rouge_2": rouge_2,
                "rouge_l": rouge_l,
            },
        )

    def _tokenize(self, text: str) -> list[str]:
        return re.findall(r"\w+", text.lower())

    def _get_ngrams(self, tokens: list[str], n: int) -> Counter:
        return Counter(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))

    def _rouge_n(self, pred: list[str], ref: list[str], n: int) -> dict:
        pred_ngrams = self._get_ngrams(pred, n)
        ref_ngrams = self._get_ngrams(ref, n)

        overlap = sum(
            min(pred_ngrams.get(k, 0), ref_ngrams.get(k, 0))
            for k in set(pred_ngrams) | set(ref_ngrams)
        )
        pred_total = sum(pred_ngrams.values())
        ref_total = sum(ref_ngrams.values())

        precision = overlap / pred_total if pred_total > 0 else 0.0
        recall = overlap / ref_total if ref_total > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def _rouge_l(self, pred: list[str], ref: list[str]) -> dict:
        lcs_len = self._lcs_length(pred, ref)
        precision = lcs_len / len(pred) if pred else 0.0
        recall = lcs_len / len(ref) if ref else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    def _lcs_length(self, a: list[str], b: list[str]) -> int:
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i - 1] == b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]


evaluator_service = EvaluatorService()
