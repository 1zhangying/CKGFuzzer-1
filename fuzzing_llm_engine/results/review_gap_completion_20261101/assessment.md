# Assessment of the completed reviewer-gap analyses

## Bottom line

The supplement materially strengthens the response but does not make every
remaining reviewer concern disappear.

- The V0/V1 decomposition is now directly answered and does not require another
  experiment.
- Target diversity and the latest cross-model comparison are now supported by
  auditable tables.
- The 145-report blind audit is fully accounted for at the report level, and
  the 26 target reports have an evidence export.
- R1.2 is now internally defensible under the paper's binary target versus
  non-target criterion. The remaining substantive risk is representative
  membership under input reordering.

## Reviewer-facing strengths

### R2.3: source of the V0/V1 difference

The V0 predictions are unchanged. Restricting them to the same 534 reports
retained by V1 raises F1 from 0.4021 to 0.6771. Applying V1 triage metadata to
that same population changes F1 from 0.6771 to 0.6485: recall rises from
0.7023 to 0.7209, but false positives rise from 80 to 108.

This directly shows that the large F1 movement is explained mainly by removing
false-positive reports from the evaluation population. All 215 current targets
remain in the retained population. The remaining 172 decision changes are
caused by the changed evidence input: 52 involve targets, with 24
target-to-non-target flips and 28 non-target-to-target flips.

This is the strongest new result and should close R2.3 if reported with the
confusion matrices.

### R2.2: target diversity

The 14 projects contain 186 drivers. Of these, 179 (96.2%) invoke at least two
distinct target-library APIs, and 168 (90.3%) show an initialization/use/cleanup
or ordered-call pattern. The added dlt-daemon and isotp-c cases provide concrete
stateful examples.

This is adequate for the requested diversity analysis, provided the manuscript
does not claim that the static pattern is a complete state-machine audit.

### R1.7/R2.4: stability and backend sensitivity

Six-run prompt results show limited run-to-run variation. P2 and P3 overlap
substantially, so the manuscript should describe their difference as
observational rather than statistically established. The latest calibrated
cross-model F1 values are tightly clustered between 0.8240 and 0.8379.

### R1.6: reproducibility metadata

The model ID, endpoint class, temperature, context size, timeout, retry policy,
backend list, and saved-artifact access window are now documented. An immutable
provider weight snapshot is not available; the frozen prompts, saved responses,
and hashes are the correct reproducibility record and should be stated as such.

## Remaining weaknesses

### R1.2: binary ground-truth criterion

The 145-report audit resolves to:

- 26 target reports;
- 62 reports confirmed as non-target by unanimous review;
- 57 reports from non-unanimous groups for which repeated local reproduction was unstable or occurred at low frequency.

All 57 non-unanimous groups were retained in the final binary ground truth as
non-target because they did not satisfy the predefined target-confirmation
criterion. Their recorded replay outcomes support this decision: reproduction
was either unstable or limited to low-frequency events. The final ground truth
therefore contains 215 targets and 1,002 non-targets over all 1,217 reports.

As a worst-case sensitivity check, treating all 57 non-unanimous audit reports
as targets changes the V4 result from `P/R/F1=0.7654/0.9256/0.8379` to
`0.7923/0.7574/0.7744`. This bound is reported as a robustness check rather
than an alternative ground truth.

The response can therefore defend binary labeling under an explicit
target-confirmation rule. The manuscript should not describe a non-target as
proof that the target component is defect-free; it should state that the status
is assigned when repeated evidence does not meet the target criterion.

### R1.3: representative-order sensitivity

Across 256 within-project permutations, the representative count remains 96,
but pairwise co-clustering agreement with the saved mapping has a mean Jaccard
of 0.1973. CVE-pair precision remains 1.0000 and root-pair precision remains
0.9899, so reordering does not introduce observed false merges. It does change
which reports become representatives and lowers CVE-pair recall from 0.4170 to
0.3161-0.3565.

This is the most important residual risk. The current evidence supports the
claim that order affects representative identity and recall. It does not support
the claim that the final reported metrics are order-invariant. A canonical order
would change roughly half of the representatives and therefore requires a
controlled rerun. Disclosing the fixed discovery order is the minimum honest
response, but a rigorous reviewer may still reject it as insufficient.

### R1.8/R2.1: connected-vehicle positioning

The new dlt-daemon and isotp-c targets improve relevance, but the work remains a
third-party-library crash-adjudication study rather than a complete connected
vehicle stack or ISO 26262 validation. This does not need another experiment if
the manuscript explicitly adopts the reviewer's offered scope narrowing.

## Submission judgment

As currently stated, the new evidence would substantially improve the response
and likely close R2.2, R2.3, R2.4, and the reproducibility part of R1.6.

It would not yet make a rigorous reviewer fully satisfied because R1.3 contains
a material order sensitivity result. R1.2 is defensible if the manuscript
states that unstable or low-frequency reproduction does not meet the predefined
target-confirmation criterion; it should not claim that every negative is
independently known to be defect-free.

A defensible submission package needs one of the following before the headline
metrics are treated as final:

1. Add a canonical-order representative run to test whether the main V4 result
   survives representative reassignment, or explicitly weaken the paper to a
   fixed-discovery-order evaluation and report the observed sensitivity.

## Files

- `r1_2_sensitivity.csv`
- `r1_2_confirmed_target_evidence_26.csv`
- `r1_3_order_sensitivity.json`
- `r1_7_prompt_stability.csv`
- `r1_7_report_level_flips.csv`
- `r1_6_model_metadata.json`
- `r2_2_target_diversity.csv`
- `r2_2_stateful_examples.csv`
- `r2_3_v0_v1_decomposition.csv`
- `r2_3_v0_v1_flips.csv`
- `r2_4_cross_model_metrics.csv`
