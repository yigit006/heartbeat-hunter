"""Katman 1 gorsellestirmesi: dedektorlerin ne yaptigini gozle gormek.

README ve sunum icin PNG'ler uretir (docs/img/). Jupyter yerine duz script:
CI'da da calisir, git diff'i temiz kalir.

Calistir: python notebooks/visualize_layer1.py
"""

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hhunter.features import schuster_periodogram  # noqa: E402
from hhunter.simulator import (  # noqa: E402
    BeaconConfig,
    beacon_timestamps,
    human_timestamps,
)

IMG = Path(__file__).resolve().parents[1] / "docs" / "img"
IMG.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"figure.dpi": 110, "font.size": 10})


def fig_periodogram() -> None:
    """Schuster periodogrami: beacon net tepe, insan duz gurultu."""
    rng = np.random.default_rng(1)
    beacon = beacon_timestamps(BeaconConfig(period=120.0, jitter=0.15), 0.0, 12 * 3600, rng)
    human = human_timestamps(30, 0.0, 12 * 3600, rng)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for ax, ts, title, color in [
        (axes[0], beacon, "Beacon (T=120s, %15 jitter)", "#c0392b"),
        (axes[1], human, "Insan trafigi (Poisson)", "#2980b9"),
    ]:
        periods, power = schuster_periodogram(ts)
        ax.semilogx(periods, power, color=color, lw=1.2)
        ax.axhline(np.log(len(power)), ls="--", color="gray", lw=1,
                   label="Poisson gurultu esigi ~ln(N)")
        ax.set_title(title)
        ax.set_xlabel("Periyot (saniye)")
        ax.set_ylabel("Schuster gucu R")
        ax.legend(fontsize=8)
    fig.suptitle("Schuster Periodogrami: gizli frekansi gurultuden ayirmak", fontweight="bold")
    fig.tight_layout()
    fig.savefig(IMG / "periodogram.png", bbox_inches="tight")
    plt.close(fig)
    print(f"yazildi: {IMG / 'periodogram.png'}")


def fig_jitter_robustness() -> None:
    """Dedektorlerin jitter'a karsi dayanikliligi (Monte Carlo)."""
    from hhunter.features import extract_features

    rng = np.random.default_rng(2026)
    jitters = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
    n = 30
    # Birlesik kural: dusuk baskin-kume CV VE yuksek destek. dom_cv TEK BASINA
    # yaniltir (kume ±%25 tanimli -> mekanik olarak dar); destek sarti sart.
    combined_rate, sig_rate, cv_rate = [], [], []
    for j in jitters:
        comb = s = c = 0
        for _ in range(n):
            T = float(np.exp(rng.uniform(np.log(30), np.log(1800))))
            ts = beacon_timestamps(BeaconConfig(period=T, jitter=j, miss_prob=0.1),
                                   0.0, 24 * 3600, rng)
            if len(ts) < 8:
                continue
            f = extract_features(ts)
            c += f["raw_cv"] < 0.3
            comb += (
                not np.isnan(f["dom_cv"])
                and f["dom_cv"] < 0.15
                and f["dom_support"] > 0.5
            )
            s += f["schuster_sig"] > 15
        cv_rate.append(100 * c / n)
        combined_rate.append(100 * comb / n)
        sig_rate.append(100 * s / n)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = [100 * j for j in jitters]
    ax.plot(x, cv_rate, "o-", label="Ham CV < 0.3 (naif)", color="#7f8c8d")
    ax.plot(x, combined_rate, "s-",
            label="Baskin-kume: dom_cv<0.15 VE destek>0.5 (RITA-esini)", color="#27ae60")
    ax.plot(x, sig_rate, "^-", label="Schuster anlamlilik > 15", color="#c0392b")
    ax.set_xlabel("Jitter (%)")
    ax.set_ylabel("Tespit orani (%)  |  bu kurallarda insan FP = %0")
    ax.set_title("Jitter Dayanikliligi: naif CV erken coker, dayanikli yontemler direnir",
                 fontweight="bold")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(IMG / "jitter_robustness.png", bbox_inches="tight")
    plt.close(fig)
    print(f"yazildi: {IMG / 'jitter_robustness.png'}")


def fig_ctu_separation() -> None:
    """CTU-13: TEK ozellik yetmez, iki ozellik birlikte ayirir.

    dom_cv tek basina yaniltir (arka plan da dusuk cikar). Gercek ayrim
    dom_cv (dusuk) VE dom_support (yuksek) kosesinde. Bu grafik Hafta 3'un
    (cok-sinyal birlesimi) deneysel gerekcesidir.
    """
    df = pd.read_parquet(Path(__file__).resolve().parents[1] / "data" / "ctu42_features.parquet")
    df = df.dropna(subset=["dom_cv", "dom_support"])
    bg = df[~df["is_botnet"]]
    cc = df[df["is_cc"]]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.scatter(bg["dom_cv"], bg["dom_support"], s=6, alpha=0.15, color="#2980b9",
               label=f"Arka plan (n={len(bg)})")
    ax.scatter(cc["dom_cv"], cc["dom_support"], s=140, marker="*", color="#c0392b",
               edgecolor="black", zorder=5, label=f"Gercek C2/CC (n={len(cc)})")
    # Karar kosesi: dusuk dom_cv VE yuksek destek
    ax.axvline(0.15, ls="--", color="black", lw=1)
    ax.axhline(0.5, ls="--", color="black", lw=1)
    ax.fill_between([0, 0.15], 0.5, 1.0, color="#27ae60", alpha=0.12)
    ax.text(0.02, 0.92, "beacon bolgesi\n(dom_cv<0.15 VE destek>0.5)",
            fontsize=8, color="#1e7d34")
    ax.set_xlim(0, 0.6)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("Baskin-kume CV (dom_cv) - dusuk = duzenli")
    ax.set_ylabel("Baskin-kume destegi (dom_support) - yuksek = burst az")
    ax.set_title("CTU-13: tek ozellik yetmez; ayrim iki boyutta - Hafta 3'un gerekcesi",
                 fontweight="bold")
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(IMG / "ctu_separation.png", bbox_inches="tight")
    plt.close(fig)
    print(f"yazildi: {IMG / 'ctu_separation.png'}")


if __name__ == "__main__":
    fig_periodogram()
    fig_jitter_robustness()
    fig_ctu_separation()
    print("Tum gorseller uretildi.")
