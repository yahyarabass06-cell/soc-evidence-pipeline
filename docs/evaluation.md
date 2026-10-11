# Evaluation Protocol

## Scope

Evaluate offline authentication detection using synthetic, authorized data.
No operational accuracy claims will be made from a small synthetic corpus.

## Fixed Default Configuration

- Failure burst: 5 failures within 120 seconds.
- Success after failures: 3 preceding failures within 120 seconds.
- Multi-account failures: 5 distinct accounts within 300 seconds.

## Evaluation Unit

For the initial corpus, evaluate each rule once per scenario:
positive means at least one alert from that rule.

Also compare alert counts and source evidence separately.
Scenario-level metrics do not measure event-level detection accuracy.

## Ground Truth

Each scenario records:
- Expected pattern presence for each rule.
- Scenario intent: benign or simulated suspicious activity.
- Expected alert counts.
- Explanation of the label.

Labels are defined before running detection.
Pattern presence and malicious intent are different labels.

## Initial Scenarios

1. Normal successful authentication.
2. Two failures followed by success.
3. Five rapid failures against one account.
4. Three failures followed by success.
5. Five distinct accounts failing from one IP.
6. Failures separated beyond the detection window.
7. Failures distributed across separate hosts.
8. Five legitimate password mistakes: intentional false-positive example
   when alerts are interpreted as malicious activity.

## Metrics

For each rule, calculate TP, FP, TN and FN against pattern labels.
Derive precision, recall and false-positive rate.
Report undefined metrics as null when their denominator is zero.

Separately report alerts on benign-intent scenarios.
Do not confuse pattern correctness with attack classification.

## Limitations

The initial corpus is small and synthetic.
It is a regression evaluation, not proof of real-world effectiveness.
Document missed patterns, benign alerts and threshold sensitivity.
Use separate scenarios for threshold tuning and later evaluation.

## Observed Initial Results

The eight-scenario corpus produced the expected alert counts.
Pattern-level confusion counts were:

| Rule | TP | FP | TN | FN |
|---|---:|---:|---:|---:|
| Failure burst | 2 | 0 | 6 | 0 |
| Success after failures | 1 | 0 | 7 | 0 |
| Multi-account failures | 1 | 0 | 7 | 0 |

These results validate only the explicitly constructed patterns.
They do not establish operational attack-detection accuracy.

The legitimate password-mistakes scenario produced an alert.
The suspicious slow and separate-host scenarios produced no alerts.

## Baseline Comparison

A baseline counts five failures per host, IP and account without a time window.

On the slow-failures scenario, the baseline alerted while the sliding-window
rule did not. This matches the defined rapid-failure pattern.

Both approaches alerted on legitimate repeated password mistakes.
Detecting slow or distributed activity requires complementary rules.

## Reproduction

From the repository root:

    python scripts/generate_evaluation_data.py
    python scripts/evaluate_detection.py --output reports/evaluation-new.json
    python scripts/compare_baseline.py

Create the reports directory first and choose a new output filename.
