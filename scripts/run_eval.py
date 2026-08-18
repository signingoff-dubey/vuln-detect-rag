"""Run evaluation metrics for the RAG system and scanner outputs."""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from services.evaluators import evaluator_service


def run_evaluation():
    print("=" * 60)
    print("  VulnDetectRAG - Evaluation Suite")
    print("=" * 60)

    # --- Test 1: CVE Detection Accuracy ---
    print("\n[1] CVE Detection Metrics")
    print("-" * 40)

    predicted_cves = [
        "CVE-2021-44228", "CVE-2023-23397", "CVE-2022-22965",
        "CVE-2023-44487", "CVE-2021-34527", "CVE-2020-1472",
        "CVE-2023-50164", "CVE-2024-23897", "CVE-2023-46747"
    ]
    ground_truth_cves = [
        "CVE-2021-44228", "CVE-2023-23397", "CVE-2022-22965",
        "CVE-2023-44487", "CVE-2021-26855", "CVE-2020-1472",
        "CVE-2023-36884", "CVE-2023-4966", "CVE-2024-23897"
    ]

    detection_result = evaluator_service.evaluate_cve_detection(predicted_cves, ground_truth_cves)
    print(f"  Accuracy:  {detection_result.details['detection_rate']}")
    print(f"  Precision: {detection_result.details['precision']}")
    print(f"  Recall:    {detection_result.details['recall']}")
    print(f"  F1 Score:  {detection_result.details['f1']}")
    print(f"  TP: {detection_result.details['true_positives']}, "
          f"FP: {detection_result.details['false_positives']}, "
          f"FN: {detection_result.details['false_negatives']}")

    # --- Test 2: BLEU Score ---
    print("\n[2] BLEU Score (RAG Answer Quality)")
    print("-" * 40)

    reference = (
        "CVE-2021-44228 is a critical remote code execution vulnerability in Apache Log4j2. "
        "The vulnerability has a CVSS score of 10.0. Attackers can exploit it by sending "
        "crafted log messages that trigger JNDI lookups. The recommended remediation is to "
        "upgrade Log4j to version 2.17.1 or later."
    )
    prediction = (
        "CVE-2021-44228 is a critical RCE vulnerability in Apache Log4j2 with CVSS score 10.0. "
        "It can be exploited through JNDI injection in log messages. "
        "Upgrade to Log4j 2.17.1 to remediate this issue."
    )

    bleu_result = evaluator_service.evaluate_bleu(prediction, reference)
    print(f"  BLEU Score: {bleu_result.score}")
    print(f"  BLEU-1: {bleu_result.details['bleu_1']}")
    print(f"  BLEU-2: {bleu_result.details['bleu_2']}")
    print(f"  BLEU-3: {bleu_result.details['bleu_3']}")
    print(f"  BLEU-4: {bleu_result.details['bleu_4']}")
    print(f"  Brevity Penalty: {bleu_result.details['brevity_penalty']}")

    # --- Test 3: ROUGE Score ---
    print("\n[3] ROUGE Score (RAG Answer Quality)")
    print("-" * 40)

    rouge_result = evaluator_service.evaluate_rouge(prediction, reference)
    print(f"  Overall ROUGE: {rouge_result.score}")
    print(f"  ROUGE-1: P={rouge_result.details['rouge_1']['precision']}, "
          f"R={rouge_result.details['rouge_1']['recall']}, "
          f"F1={rouge_result.details['rouge_1']['f1']}")
    print(f"  ROUGE-2: P={rouge_result.details['rouge_2']['precision']}, "
          f"R={rouge_result.details['rouge_2']['recall']}, "
          f"F1={rouge_result.details['rouge_2']['f1']}")
    print(f"  ROUGE-L: P={rouge_result.details['rouge_l']['precision']}, "
          f"R={rouge_result.details['rouge_l']['recall']}, "
          f"F1={rouge_result.details['rouge_l']['f1']}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  Evaluation Summary")
    print("=" * 60)
    print(f"  CVE Detection F1:    {detection_result.details['f1']:.4f}")
    print(f"  BLEU Score:          {bleu_result.score:.4f}")
    print(f"  ROUGE Score:         {rouge_result.score:.4f}")
    print("=" * 60)

    return {
        "detection_f1": detection_result.details['f1'],
        "bleu": bleu_result.score,
        "rouge": rouge_result.score,
    }


if __name__ == "__main__":
    run_evaluation()
