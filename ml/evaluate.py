"""Evaluate the detection engine on a labelled URL dataset (Phase 5 testing).

    python ml/evaluate.py                       # rules only, sample dataset
    python ml/evaluate.py --ml                  # rules + trained ML model
    python ml/evaluate.py --data my.csv --errors 20

A URL counts as "predicted phishing" when classified Suspicious or Likely
Phishing (strict mode: only Likely Phishing, use --strict).
"""
from __future__ import annotations

import argparse
from collections import Counter

from common import DEFAULT_DATA, DEFAULT_MODEL, load_dataset

from app.detection import PHISHING, SUSPICIOUS, URLValidationError, analyze


def main():
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard detection")
    parser.add_argument("--data", default=DEFAULT_DATA)
    parser.add_argument("--ml", action="store_true", help="blend in the trained model")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--strict", action="store_true",
                        help="only 'Likely Phishing' counts as a phishing prediction")
    parser.add_argument("--errors", type=int, default=10, help="misclassified examples to show")
    args = parser.parse_args()

    urls, labels = load_dataset(args.data)
    tp = tn = fp = fn = invalid = 0
    by_class = Counter()
    mistakes = []
    for url, y in zip(urls, labels):
        try:
            r = analyze(url, model_path=args.model if args.ml else None, use_ml=args.ml)
        except URLValidationError:
            invalid += 1
            continue
        by_class[(y, r.classification)] += 1
        positive = {PHISHING} if args.strict else {PHISHING, SUSPICIOUS}
        pred = 1 if r.classification in positive else 0
        if pred and y:
            tp += 1
        elif not pred and not y:
            tn += 1
        elif pred and not y:
            fp += 1
            mistakes.append(("FALSE POSITIVE", url, r.classification, r.score))
        else:
            fn += 1
            mistakes.append(("FALSE NEGATIVE", url, r.classification, r.score))

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    mode = "rules + ML" if args.ml else "rules only"
    print(f"Evaluated {total} URLs ({mode}, {'strict' if args.strict else 'normal'} mode); "
          f"{invalid} invalid skipped")
    print(f"  accuracy   {(tp + tn) / total:.4f}")
    print(f"  precision  {precision:.4f}")
    print(f"  recall     {recall:.4f}")
    print(f"  f1         {f1:.4f}")
    print(f"  confusion  TN={tn} FP={fp} FN={fn} TP={tp}")
    print("\n  Classification breakdown:")
    for y_label, name in ((0, "legitimate"), (1, "phishing")):
        row = ", ".join(f"{c}: {by_class[(y_label, c)]}"
                        for c in ("Likely Safe", "Suspicious", "Likely Phishing"))
        print(f"    {name:<11} -> {row}")
    if mistakes and args.errors:
        print(f"\n  Sample of misclassified URLs (showing {min(args.errors, len(mistakes))} "
              f"of {len(mistakes)}):")
        for kind, url, cls, score in mistakes[:args.errors]:
            print(f"    [{kind}] {cls} ({score})  {url}")


if __name__ == "__main__":
    main()
