"""Simulator testleri: urettigimiz veri iddia ettigimiz istatistiklere sahip mi?"""

import numpy as np
import pytest

from hhunter.simulator import (
    BeaconConfig,
    beacon_timestamps,
    generate_dataset,
    human_timestamps,
)


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(7)


def test_beacon_period_and_jitter(rng: np.random.Generator) -> None:
    cfg = BeaconConfig(period=60.0, jitter=0.1)
    ts = beacon_timestamps(cfg, start=0.0, duration=6 * 3600, rng=rng)
    deltas = np.diff(ts)
    # Ortalama aralik ~ periyot
    assert abs(deltas.mean() - 60.0) < 2.0
    # Jitter siniri: her aralik [54, 66] icinde
    assert deltas.min() >= 54.0 and deltas.max() <= 66.0
    # Dusuk varyasyon katsayisi: makine trafigi imzasi
    assert deltas.std() / deltas.mean() < 0.1


def test_miss_prob_reduces_count(rng: np.random.Generator) -> None:
    cfg_full = BeaconConfig(period=60.0, miss_prob=0.0)
    cfg_missy = BeaconConfig(period=60.0, miss_prob=0.3)
    n_full = len(beacon_timestamps(cfg_full, 0.0, 6 * 3600, np.random.default_rng(1)))
    n_missy = len(beacon_timestamps(cfg_missy, 0.0, 6 * 3600, np.random.default_rng(1)))
    assert n_missy < n_full
    # Kabaca %30 eksik
    assert 0.55 < n_missy / n_full < 0.85


def test_human_traffic_is_poisson_like(rng: np.random.Generator) -> None:
    ts = human_timestamps(rate_per_hour=30, start=0.0, duration=24 * 3600, rng=rng)
    deltas = np.diff(ts)
    # Poisson surecinde araliklarin CV'si ~1 (ustel dagilim). Genis tolerans.
    cv = deltas.std() / deltas.mean()
    assert 0.8 < cv < 1.2


def test_generate_dataset_schema_and_labels() -> None:
    df = generate_dataset(n_beacons=3, n_human=10, duration=6 * 3600, seed=42)
    assert set(["ts", "src_ip", "dst_ip", "dst_port", "orig_bytes", "is_beacon"]).issubset(
        df.columns
    )
    # Etiketler her iki sinifi da icermeli
    assert df["is_beacon"].any() and (~df["is_beacon"]).any()
    # Beacon kaynaklari 10.0.0.x, insan kaynaklari 10.0.1.x
    assert df[df["is_beacon"]]["src_ip"].str.startswith("10.0.0.").all()
    assert df[~df["is_beacon"]]["src_ip"].str.startswith("10.0.1.").all()


def test_deterministic_with_seed() -> None:
    a = generate_dataset(n_beacons=2, n_human=5, duration=3600, seed=99)
    b = generate_dataset(n_beacons=2, n_human=5, duration=3600, seed=99)
    assert a.equals(b)
