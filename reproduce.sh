#!/usr/bin/env bash
# Regenerate every replay and revision output from the public AgentDojo trajectories.
# Usage: bash reproduce.sh <path-to-agentdojo-repo>/runs    (repository at commit 089ed468)
# Requires: python 3.11, numpy, scipy, matplotlib, agentdojo==0.1.35. No model inference or API keys.
set -euo pipefail
RUNS="$(cd "$1" && pwd)"
cd "$(dirname "$0")/code"
ln -sfn ../artifacts artifacts
mkdir -p out
# 1. Original replay (V2): ground truth, GPT-4o replay, clustered bootstrap
python extract_groundtruth.py
python evaluate.py --runs "$RUNS/gpt-4o-2024-05-13" --out out/run_main_check > /dev/null
python analyse.py --rows out/run_main_check/replay_rows_prespecified.csv --out out/run_main_check/analysis.json
# 2. Revision analyses
python extend.py "$RUNS/gpt-4o-2024-05-13" out/main.csv "$RUNS/gpt-4o-2024-05-13-tool_filter"
python extend.py "$RUNS/gpt-4o-2024-05-13" out/main_fix.csv "$RUNS/gpt-4o-2024-05-13-tool_filter" fix_v111
for p in "$RUNS"/*; do
  n=$(find "$p" -name '*.json' | wc -l)
  if [ "$n" = "753" ]; then python extend.py "$p" "out/m_$(basename "$p").csv" "$RUNS/gpt-4o-2024-05-13-tool_filter" > /dev/null; fi
done
python rev_analysis.py out/main.csv out/main_analysis.json > /dev/null
python rev_analysis.py out/main_fix.csv out/main_fix.json > /dev/null
python stats.py
python residual.py "$RUNS/gpt-4o-2024-05-13" .. > /dev/null
python multimodel.py > /dev/null
python pooled_models.py > /dev/null
python adjudicate.py "$RUNS/gpt-4o-2024-05-13"
python draw_adjudication_sample.py > /dev/null
python utility_counts.py
python compare_versions.py
python figs.py
python ../verify.py
