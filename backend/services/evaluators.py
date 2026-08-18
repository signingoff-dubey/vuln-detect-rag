import math
import re
from collections import Counter
from models.schemas import EvalResult


class EvaluatorService:
    """Compute evaluation metrics for RAG and scanner outputs."""

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
