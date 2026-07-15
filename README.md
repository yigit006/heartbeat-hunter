[![CI](https://github.com/yigit006/heartbeat-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/yigit006/heartbeat-hunter/actions)

🇬🇧 **English** | 🇹🇷 [Türkçe](README.tr.md)

# Heartbeat Hunter

A statistics-first C2 beaconing detection engine. It hunts jittered
command-and-control traffic in Zeek `conn.log` data with pure math:
time-series analysis, probabilistic scoring and graph analysis.

> **Status:** v0.1 complete — evaluated on 4 CTU-13 scenarios (Neris ×3 + Virut).
> MITRE ATT&CK: [T1071](https://attack.mitre.org/techniques/T1071/) (Application
> Layer Protocol), [T1573](https://attack.mitre.org/techniques/T1573/) (Encrypted
> Channel) — detection relies on timing/size behaviour, not content signatures.

## Why?

A C2 implant checks in with its server at regular intervals. Attackers hide
this with jitter — but statistics don't lie. Heartbeat Hunter works in three
layers:

1. **Time-series analysis** — robust distribution statistics (dominant-cluster CV, MAD, Bowley skewness) + Schuster/Rayleigh periodogram
2. **Probabilistic scoring** — multiple signals combined into a composite score
3. **Graph analysis** — from anomaly to campaign detection

## Method (Layer 1)

Beacons connect at regular intervals; attackers mask this with jitter.
We use two complementary methods:

**Dominant-cluster distribution** (inspired by RITA): real C2 traffic mixes
retry/multi-request bursts in between beacon intervals, so the raw
coefficient of variation misleads. Instead we find the densest mode of the
inter-arrival distribution and measure the spread inside that cluster. A low
cluster-CV alone is not enough (the cluster is narrowly defined, so its CV is
mechanically small) — it is used together with **cluster support** (the share
of intervals that fall into the cluster).

![Jitter robustness](docs/img/jitter_robustness.png)

**Schuster periodogram**: `R(f) = |Σ exp(2πi·f·tⱼ)|² / n`. A direct frequency
scan over event times — no binning required (works where the FFT fails on
irregular sampling), and under Poisson noise `R ~ Exp(1)`, so statistical
significance comes analytically for free.

![Schuster periodogram](docs/img/periodogram.png)

On CTU-13 Scenario 42 (Neris): no single feature separates the C2 channels
from the background — the experimental justification for Layer 2
(multi-signal fusion).

![CTU-13 separation](docs/img/ctu_separation.png)

## Method (Layer 2): composite score + funnel

A RITA-style weighted composite score that works without labels: time
subscores (dominant-cluster, MAD, Schuster) + **byte subscores** (beacon
payloads have fixed sizes — bursts distort timing but not bytes) + context
(destination rarity, persistence, port category). Significance is verified
empirically with a BAYWATCH-style bucket-permutation test.

The score alone is not enough: in the CTU-42 exam the entire top-20 was
legitimate periodic infrastructure (NTP, SNMP, internal monitoring). The
literature's answer is a **filter**, not a weight (BAYWATCH funnel, Elastic
direction filter): the score measures "beacon-likeness", while the scope
filter (external destination + non-infrastructure port) narrows the C2
search space. Result: 12,220 pairs → 4,958 candidates; NTP/SNMP cleared from
the list, and all four C2 channels rose 2-3× in rank.

```bash
hhunter score pairs.parquet --internal-net 147.32.0.0/16   # in-scope list
hhunter score pairs.parquet --all                          # raw ranking
```

## Method (Layer 3): graph — from anomaly to campaign

One beacon is an anomaly; ≥2 internal machines beaconing to the same
destination **with a similar period** is a campaign. Scored channels go into
a bipartite graph (source↔destination); shared destinations receive a
combined `campaign_score` from period coherence and channel scores.

**Multi-host exam (CTU-13 Scenario 9, Neris, 10 bots):** single-channel
scoring could only place the first C2 at rank 67; the campaign layer put
**the real C2 (195.190.13.70, 7 bots, 115 s, coherence 1.0) at rank 1**. The
main C2 buried at rank 8,177 in Scenario 42 (173.192.170.88) became campaign
#5 through the collective evidence of 8 bots. 7 of the top-10 campaigns were
botnet infrastructure — including spam/click-fraud channels that carry no CC
label (beyond-label detection). Honest limit: in a single-infected-host
capture (S42) this layer mechanically cannot fire (≥2 sources required) —
there: 55 candidates / 0 CC.

```bash
hhunter campaign scored.parquet          # campaign candidates
```

## Evaluation (CTU-13, in-scope candidates)

![PR curves](docs/img/pr_curves.png)

| Scenario | First CC: naive −CV | First CC: composite | R@100: naive | R@100: composite |
|---|---|---|---|---|
| S1/42 (Neris, 1 bot) | 59 | **37** | 0.25 | 0.25 |
| S2/43 (Neris, 1 bot) | 869 | **89** | 0.00 | **0.17** |
| S9/50 (Neris, 10 bots) | 87 | **46** | 0.16 | 0.10 (R@500: 0.27→**0.41**) |
| S13/54 (Virut, 1 bot) | 1,091 | **89** | 0.00 | **0.25** |

The composite score improves the first-CC rank in all four scenarios: 10× on
S2 and 12× on a family never seen during tuning (Virut). In the multi-bot S9
the extra layer kicks in: **at campaign level the real C2 ranks #1 among 94
candidates** (in single-bot captures the ≥2-source requirement mechanically
cannot be met — an honest limit).

Layered reading: at channel level, isolating C2 among thousands of legitimate
periodic pollers (mail, monitoring, updates) is the shared difficulty of all
statistical detectors (AP ≈ 0.03). The tool's real hunt list is the
**campaign level** — the real C2 ranks 1st among 94 candidates. Two design
lessons were documented with measurements: the destination-rarity signal
inverts in multi-bot captures (removed from the channel score, moved to the
campaign layer), and the Rbot scenarios (S10/S11) are out of evaluation scope
because they contain no measurable CC beaconing density.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage (end-to-end pipeline)

```bash
# 1) Zeek conn.log or CTU-13 .binetflow -> pair table
hhunter ingest capture.binetflow -o pairs.parquet

# 2) Scoring (declare your organisation's public block as internal)
hhunter score pairs.parquet --internal-net 147.32.0.0/16 -o scored.parquet

# 3) Campaign detection (>=2 internal sources to the same destination)
hhunter campaign scored.parquet

# JSON output on both commands for SIEM/automation:
hhunter score pairs.parquet --json | jq '.[0]'
hhunter campaign scored.parquet --json
```

## Analysis panel (Streamlit)

The human-friendly face of the CLI funnel — the panel only reads; all
analysis happens in the pipeline (no second computation path):

```bash
pip install -e ".[demo]"
streamlit run app.py
```

Three views: filtered candidate table, channel detail (timeline +
inter-arrival distribution + periodogram + subscore breakdown — the answer to
"why is this score high?") and the campaign list.

## Limitations (measured and documented)

- **50%+ jitter** is the detection limit — intervals genuinely turn into
  noise at that point (robustness matrix: `docs/img/jitter_robustness.png`).
- **Channel-level AP is low** (~0.03): thousands of legitimate periodic
  pollers (mail, monitoring, updates) carry the same temporal signature as a
  beacon. This tool is a triage funnel, not a verdict machine.
- **The campaign layer requires ≥2 infected sources** — it mechanically
  cannot fire on single-bot captures.
- **Rbot/DDoS scenarios (S10/S11) could not be evaluated**: they contain no
  measurable CC beaconing density — reported as a data-suitability analysis.
- Future work: PU-learning for few-positive calibration, Elastic-style bucket
  autocorrelation (high jitter); moving the ingestion layer to
  Polars/lazy-scan for 50GB+/day scale (the schema is source-agnostic, so the
  change stays confined to `ingest.py` — pandas was a deliberate choice at
  this scale: 2.8M flows in 14 s).

## Roadmap

- [x] Week 1: Zeek conn.log ingestion + beacon simulator
- [x] Week 2: Time-series layer (dominant-cluster CV, MAD, Bowley, Schuster periodogram)
- [x] Week 3: Composite scoring (time+bytes+context) + permutation significance + funnel filter
- [x] Week 3: Graph analysis / campaign detection (networkx) — `hhunter campaign`
- [x] Week 4: Multi-host scenario (S9) + evaluation infrastructure + PR curves
- [x] Week 4: Evaluation on 4 scenarios (Neris ×3 + Virut) — cross-family generalisation
- [x] Week 4: CLI `--json` (SIEM integration) + limitations documentation
- [x] Bonus: Streamlit analysis panel (`streamlit run app.py`)

## License

MIT
