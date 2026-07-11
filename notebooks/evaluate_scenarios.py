"""Hafta 4 degerlendirme: coklu senaryoda PR egrileri + baseline karsilastirmasi.

Uc siralayici karsilastirilir (hepsi ayni kapsam-ici aday kumesi uzerinde):
1. naif-CV     : -raw_cv (dusuk varyasyon = beacon) - Hafta 1'in cuvallayan baseline'i
2. bilesik skor: Katman 2 (zaman+bayt+baglam agirlikli ortalama)
3. skor+kampanya: kanal skoru, hedefi bir kampanyadaysa campaign_score ile
   yukseltilir: max(score, campaign_score). Katman 3'un kolektif kanitinin
   kanal siralamasina geri beslenmesi.

Metrikler:
- AP (average precision): PR egrisinin alti - esiksiz, siralama kalitesi
- P@20 / R@50: FP butcesi perspektifi ("analistim gunde 20 alarma bakar")

Kullanim (repo kokunden):
    python notebooks/evaluate_scenarios.py

Girdi: data/ctu42_scored.parquet, data/ctu09_scored.parquet (score ciktilari)
Cikti: docs/img/pr_curves.png + stdout metrik tablosu
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from hhunter.campaign import detect_campaigns

DATA = Path(__file__).resolve().parents[1] / "data"
IMG = Path(__file__).resolve().parents[1] / "docs" / "img"

SCENARIOS = {
    "S1/42 (Neris, 1 bot)": "ctu42_scored.parquet",
    "S9/50 (Neris, 10 bot)": "ctu09_scored.parquet",
}


def pr_curve(y: np.ndarray, s: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
    """Precision-recall egrisi + AP. y: 0/1, s: skor (buyuk = pozitif tahmini)."""
    order = np.argsort(-s, kind="stable")
    y = y[order]
    tp = np.cumsum(y)
    n_pos = int(y.sum())
    precision = tp / np.arange(1, len(y) + 1)
    recall = tp / max(n_pos, 1)
    # AP: her pozitifin bulundugu siradaki precision'larin ortalamasi
    ap = float(precision[y == 1].mean()) if n_pos else float("nan")
    return precision, recall, ap


def rankers(scored: pd.DataFrame) -> dict[str, np.ndarray]:
    """Uc siralayicinin skor vektorleri (kapsam-ici aday kumesi uzerinde)."""
    camps = detect_campaigns(scored)
    boost = dict(zip(camps["dst_ip"], camps["campaign_score"]))
    cand = scored[scored["in_scope"]].reset_index(drop=True)
    naive = -cand["raw_cv"].fillna(cand["raw_cv"].max()).to_numpy()
    composite = cand["score"].to_numpy()
    boosted = np.maximum(composite, cand["dst_ip"].map(boost).fillna(0.0).to_numpy())
    return {
        "naif -CV": naive,
        "bilesik skor": composite,
        "skor+kampanya": boosted,
    }, cand


def main() -> None:
    fig, axes = plt.subplots(1, len(SCENARIOS), figsize=(11, 4.2), sharey=True)
    rows = []
    for ax, (label, fname) in zip(np.atleast_1d(axes), SCENARIOS.items()):
        scored = pd.read_parquet(DATA / fname)
        scores, cand = rankers(scored)
        y = cand["is_cc"].to_numpy().astype(int)
        for name, s in scores.items():
            precision, recall, ap = pr_curve(y, s)
            ax.plot(recall, precision, label=f"{name} (AP={ap:.3f})", lw=2)
            order = np.argsort(-s, kind="stable")
            ranks = np.where(y[order] == 1)[0] + 1
            first = int(ranks[0]) if len(ranks) else -1
            r100 = (ranks <= 100).sum() / max(y.sum(), 1)
            r500 = (ranks <= 500).sum() / max(y.sum(), 1)
            rows.append((label, name, ap, first, r100, r500))
        # Kampanya (hedef) duzeyi: aracin asil av listesi
        camps = detect_campaigns(scored)
        cc_dsts = set(scored[scored["is_cc"]]["dst_ip"])
        hits = [i + 1 for i, d in enumerate(camps["dst_ip"]) if d in cc_dsts]
        rows.append((label, "KAMPANYA (hedef duzeyi)", float("nan"), hits[0] if hits else -1,
                     np.nan, np.nan))
        print(f"{label}: {len(camps)} kampanya adayi, CC-hedef siralari: {hits or 'yok'}")
        ax.set_title(f"{label} - {int(y.sum())} CC / {len(y):,} aday")
        ax.set_xlabel("Recall")
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
    np.atleast_1d(axes)[0].set_ylabel("Precision")
    fig.suptitle("C2 kanal siralamasi: baseline vs bilesik skor vs kampanya-guclendirmeli")
    fig.tight_layout()
    IMG.mkdir(parents=True, exist_ok=True)
    fig.savefig(IMG / "pr_curves.png", dpi=130)
    print(f"Kaydedildi: {IMG / 'pr_curves.png'}\n")

    tbl = pd.DataFrame(rows, columns=["senaryo", "siralayici", "AP", "ilk-CC", "R@100", "R@500"])
    print(tbl.to_string(index=False, float_format=lambda x: f"{x:.3f}"))


if __name__ == "__main__":
    main()
