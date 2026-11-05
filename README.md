# log-attack-detector

Detects web attacks in access logs using regex rules, per-client thresholds and an ML model, then compares them with precision and recall on payloads the model never saw in training.

> ⚠️ Benchmarks use bundled synthetic data, and the rules were written with knowledge of its attack families. Treat the numbers as a method comparison, not as real-world performance.

## Run

```bash
pip install -r requirements.txt
python detector.py benchmark          # compare detectors (--seed N, --json)
python detector.py scan access.log    # run the rules on a combined-format log
pytest
```

## Results (`benchmark`, seed 1, 20,000 test lines, 12% attacks)

| Detector | Precision | Recall | F1 | FP | FN |
| --- | --- | --- | --- | --- | --- |
| rules | 1.000 | 0.674 | 0.805 | 0 | 784 |
| ml | 0.736 | 0.873 | 0.798 | 753 | 306 |
| hybrid | 0.746 | 0.923 | 0.825 | 753 | 185 |

- Rules stay precise but miss new syntax and double encoding: traversal recall is only 0.258.
- All 753 ML false positives come from two URLs. The model sees URLs only, so it learned that `/login` means attack and flagged 546 benign failed logins, which is why behaviour needs its own detector.
- Client IPs are excluded from the features: in generated data they would give away the label.
