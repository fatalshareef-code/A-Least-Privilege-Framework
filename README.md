# Artifact: archived-trajectory replay of task-scoped, destination-bound authorization

Offline counterfactual replay of the public AgentDojo v1 archived run trajectories against frozen
access-control policies. No language model is invoked and no API credentials are needed. Every number
in Section 5 of the manuscript is produced by the code in `code/` from the inputs in `artifacts/` and the
public trajectories at AgentDojo commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60` (agentdojo 0.1.35).

## Reproduce everything (about one minute on a laptop)

    pip install numpy scipy matplotlib agentdojo==0.1.35
    git clone https://github.com/ethz-spylab/agentdojo.git && (cd agentdojo && git checkout 089ed468)
    bash reproduce.sh agentdojo/runs

`reproduce.sh` reruns the original replay and every revision analysis, then `verify.py` checks that the
regenerated files are byte-identical to the released ones.

## Contents

| Path | What it is |
|---|---|
| `code/extract_groundtruth.py` | Ground-truth extraction from AgentDojo v1 (legitimate and injection tasks kept separate) |
| `code/policy.py` | Frozen policy definitions: configurations C1 to C3, destination schemas, high-impact tools |
| `code/evaluate.py` | Replay engine and attacker-call labelling |
| `code/analyse.py` | Clustered-bootstrap analysis of the original replay |
| `code/figures.py` | Figure code of the original replay package |
| `code/extend.py` | Revision replay: alternative plans (C2tf, C3p, C3tf), all-benign-call and clean-run utility, destination strata, optional v1.1.1 ground-truth fix |
| `code/rev_analysis.py` | Containment, preservation and utility proxies with cluster-bootstrap intervals (Tables 8 and 9) |
| `code/stats.py` | Four-way cluster-robust and wild cluster bootstrap intervals (Table 6) |
| `code/residual.py` | Enforcement attribution and residual breakdown (Table 7, Section 5.7.2) |
| `code/multimodel.py`, `code/pooled_models.py` | 16 backbones, pooled estimate and defended pipelines (Section 5.3, Table 10) |
| `code/adjudicate.py`, `code/draw_adjudication_sample.py`, `code/verdicts.csv` | Label adjudication: candidate list, stratified sample (seed 20261106) and recorded verdicts (Section 5.2.3) |
| `code/utility_counts.py` | Raw numerators and denominators of the utility proxies |
| `code/compare_versions.py` | Ground-truth comparison of AgentDojo v1 with v1.1 to v1.2.1 (Section 5.2.1) |
| `code/figs.py` | Manuscript Figures 1 to 6 |
| `artifacts/` | Frozen policy inputs (ground truth, suite tools) and row-level outputs of the original replay for all five GPT-4o pipelines (`run_*`), with manifests and analysis outputs |
| `revision_outputs/row_level/` | Row-level revision outputs for the GPT-4o pipeline, the v1.1.1 sensitivity run, the four defended GPT-4o pipelines and 17 further backbones (two with fewer than 20 attempted attacks are excluded from the paper's pooled results) |
| `revision_outputs/*.json, *.csv` | Analysis outputs reported in the manuscript; `label_adjudication_sample.csv` is the adjudication sheet |
| `figures/manuscript/` | Figures as published in the revision; `figures/v2_original/` figures of the original replay |
| `supplementary/` | Layer 3 prototype figure and timing table moved out of the manuscript |
| `environment.json` | Versions, benchmark commit, seeds, replicate count |
| `checksums.json` | SHA-256 of every file; `analysis_inputs.json` maps each analysis output to the SHA-256 of its input |

## Adjudication sheet

`revision_outputs/label_adjudication_sample.csv` has one row per sampled run (unique key: suite,
user task, injection task, attack template). `stratum` is the sampling group (marker, fallback,
coincident); the groups are disjoint by construction, with population sizes 1,491, 203 and 418 attempted
runs, which are the weights. `adjudication` and `note` are the recorded verdicts. The column `verdict` is
an automatic pre-screen used only to build the candidate list, not the adjudication. Criterion: a run is
an attack attempt when a labelled call follows exposure to the injected payload and its arguments realize
the injection task's goal rather than the user's request.

## Ordering guarantee

`policy.py` reads only legitimate user-task ground truth and static tool semantics. Injection ground
truth is loaded in `evaluate.py` after policies are built and is used only to label attacker calls.
