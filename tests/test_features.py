"""Katman 1 dedektor testleri: simulatorle uretilen veride matematik dogrulanir."""

import numpy as np
import pytest

from hhunter.features import (
    collapse_bursts,
    delta_stats,
    dominant_interval,
    extract_features,
    periodicity_features,
)
from hhunter.simulator import BeaconConfig, beacon_timestamps, human_timestamps


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(11)


def _beacon(rng, period=60.0, jitter=0.2, hours=6, miss=0.0):
    cfg = BeaconConfig(period=period, jitter=jitter, miss_prob=miss)
    return beacon_timestamps(cfg, start=0.0, duration=hours * 3600, rng=rng)


def test_collapse_bursts() -> None:
    # 60sn'lik beacon, her beacon 3 hizli baglanti aciyor (gercek C2 deseni)
    base = np.arange(0, 600, 60.0)
    bursty = np.sort(np.concatenate([base, base + 0.3, base + 0.9]))
    collapsed = collapse_bursts(bursty, gap=5.0)
    assert len(collapsed) == len(base)
    # Katlama sonrasi periyot geri gelir
    assert delta_stats(collapsed)["cv"] < 0.01


def test_bursty_beacon_raw_cv_fails_collapsed_works(rng) -> None:
    """CTU-13 dersinin birebir kaniti: ham CV yaniltir, katlanmis CV yakalar."""
    base = _beacon(rng, period=60.0, jitter=0.1)
    extra = np.concatenate([base + rng.uniform(0.1, 2.0), base + rng.uniform(0.1, 3.0)])
    bursty = np.sort(np.concatenate([base, extra]))
    feats = extract_features(bursty)
    assert feats["raw_cv"] > 0.8  # ham CV: "rastgele gibi" der (yanlis)
    assert feats["col_cv"] < 0.15  # katlanmis: beacon'i gorur (dogru)


def test_mad_cv_robust_to_outlier(rng) -> None:
    """Tek uzun sessizlik (implant uyudu) CV'yi bozar, MAD-CV'yi bozmaz."""
    ts = _beacon(rng, period=60.0, jitter=0.05)
    ts_gap = np.concatenate([ts[: len(ts) // 2], ts[len(ts) // 2 :] + 4 * 3600])
    s = delta_stats(ts_gap)
    assert s["cv"] > 0.5  # klasik CV patladi
    assert s["mad_cv"] < 0.1  # dayanikli CV sakin


def test_schuster_finds_period_under_jitter(rng) -> None:
    for jitter in (0.0, 0.1, 0.25):
        ts = _beacon(rng, period=120.0, jitter=jitter, hours=12)
        p = periodicity_features(ts)
        assert abs(p["period_est"] - 120.0) / 120.0 < 0.05, f"jitter={jitter}"
        # %25 jitter'da bile sig ~9 (p ~ e^-9); Poisson maks ~3 - ayrisma net
        assert p["schuster_sig"] > 8, f"jitter={jitter}"


def test_schuster_survives_missing_beacons(rng) -> None:
    ts = _beacon(rng, period=60.0, jitter=0.1, miss=0.3)
    p = periodicity_features(ts)
    assert abs(p["period_est"] - 60.0) / 60.0 < 0.05
    assert p["schuster_sig"] > 10


def test_poisson_not_flagged(rng) -> None:
    """Rastgele trafik anlamli periyodiklik GOSTERMEMELI (FP kontrolu).

    Not: sig = R - ln(N) Gumbel dalgalanmasiyla 0-6 arasi gezinebilir;
    kesin karar esigi degil, skorlama katmaninin girdisidir. Beacon'da
    tipik degerler >> 8 (jitter=0.1'de ~47, jitter=0'da ~350).
    """
    for _ in range(3):
        ts = human_timestamps(rate_per_hour=40, start=0.0, duration=24 * 3600, rng=rng)
        p = periodicity_features(ts)
        assert p["schuster_sig"] < 8


def test_dominant_interval_isolates_beacon_from_bursts(rng) -> None:
    """RITA-esini: burst'ler ham CV'yi bozar ama baskin kume beacon'i gorur."""
    base = _beacon(rng, period=60.0, jitter=0.1)
    # Her beacon'a 1-2 hizli retry ekle (gercek C2 deseni)
    extra = np.concatenate([base + rng.uniform(0.1, 2.0), base + rng.uniform(0.1, 2.0)])
    bursty = np.sort(np.concatenate([base, extra]))
    assert delta_stats(bursty)["cv"] > 0.8  # ham CV yaniltir
    dom = dominant_interval(bursty)
    assert dom["dom_cv"] < 0.25  # baskin kume temiz
    # dom_mode ya beacon periyodu (60) ya da burst araligi olabilir; ikisi de dar kume


def test_dominant_interval_on_clean_beacon(rng) -> None:
    ts = _beacon(rng, period=90.0, jitter=0.05)
    dom = dominant_interval(ts)
    assert abs(dom["dom_mode"] - 90.0) / 90.0 < 0.15
    assert dom["dom_support"] > 0.8  # neredeyse tum araliklar tek kumede
    assert dom["dom_cv"] < 0.1


def test_dom_support_distinguishes_human_from_beacon(rng) -> None:
    """dom_cv TEK BASINA yaniltir (kume ±%25 -> mekanik dar). Ayirici: dom_support.

    Beacon'da destek yuksek (araliklarin cogu tek modda); Poisson'da dusuk
    (mod bir artefakt). Bu test, birlesik kuralin varlik sebebini kilitler.
    """
    beacon = dominant_interval(_beacon(rng, period=90.0, jitter=0.1))
    supports = []
    for _ in range(10):
        ts = human_timestamps(rate_per_hour=30, start=0.0, duration=24 * 3600, rng=rng)
        d = dominant_interval(ts)
        supports.append(d["dom_support"])
    assert beacon["dom_support"] > 0.6
    assert np.median(supports) < 0.4  # insan modu zayif destekli


def test_extract_features_keys(rng) -> None:
    feats = extract_features(_beacon(rng))
    for key in ("raw_cv", "col_cv", "col_mad_cv", "dom_mode", "dom_cv", "period_est", "schuster_sig"):
        assert key in feats


def test_extract_features_caps_giant_series(rng) -> None:
    """Dev seri korumasi: 415k olayli DNS kanali (S9 gercegi) analizi kilitlememeli.

    Bas-pencere kirpmasi periyodikligi korur: kirpilmis beacon hala beacon.
    n_events HAM sayiyi raporlar (kullanici kanalin gercek boyutunu gormeli).
    """
    ts = np.arange(0, 60.0 * 50_000, 60.0)  # 50k olayli mukemmel beacon
    feats = extract_features(ts, max_events=20_000)
    assert feats["n_events"] == 50_000  # ham sayi korunur
    assert feats["dom_cv"] < 0.05  # kirpilmis seri hala temiz beacon
    # NOT: period_est burada iddia edilmez - jitter'siz mukemmel tarakta tum
    # harmonikler tam guc alir (gunluk Bolum 6'daki tuzak); testin konusu
    # kirpma mekanigi. Periyot dogrulugu dom_mode ile kilitlenir:
    assert abs(feats["dom_mode"] - 60.0) / 60.0 < 0.01
