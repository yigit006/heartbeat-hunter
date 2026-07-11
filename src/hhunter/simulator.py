"""Beacon simulatoru: dogru cevabi bildigimiz sentetik trafik uretir.

Iki tur trafik:
- Beacon: periyodik + jitter (C2 implant davranisi). Aralik = periyot * (1 +- jitter).
- Insan/arka plan: Poisson sureci (ustel dagilimli araliklar, CV ~= 1).

Cikti, ingest.read_conn_log ile ayni semada DataFrame: boru hattinin geri kalani
gercek veriyle sentetik veri arasindaki farki bilmez. 'is_beacon' kolonu
ground-truth etikettir (sadece degerlendirme icin).
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class BeaconConfig:
    """Tek bir beacon ciftinin parametreleri."""

    period: float = 60.0  # saniye
    jitter: float = 0.1  # periyodun orani: 0.1 => +-%10
    miss_prob: float = 0.0  # beacon'in atlanma olasiligi (implant uyudu, ag koptu...)
    payload_bytes: int = 120  # tipik sabit boyutlu check-in
    payload_noise: int = 5  # bayt boyutundaki kucuk oynama


def beacon_timestamps(
    config: BeaconConfig,
    start: float,
    duration: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """Jitter'li periyodik zaman damgalari uret.

    Model: t[i+1] = t[i] + period * (1 + U(-jitter, +jitter))
    Her adimda miss_prob olasilikla baglanti atlanir (zaman ilerler, kayit dusmez).
    """
    times: list[float] = []
    t = start
    while t < start + duration:
        if rng.random() >= config.miss_prob:
            times.append(t)
        t += config.period * (1.0 + rng.uniform(-config.jitter, config.jitter))
    return np.array(times)


def human_timestamps(
    rate_per_hour: float,
    start: float,
    duration: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """Poisson sureci: insan/arka plan trafigi. Araliklar ustel dagilimli."""
    mean_gap = 3600.0 / rate_per_hour
    times: list[float] = []
    t = start + rng.exponential(mean_gap)
    while t < start + duration:
        times.append(t)
        t += rng.exponential(mean_gap)
    return np.array(times)


def _pair_frame(
    ts: np.ndarray,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    is_beacon: bool,
    rng: np.random.Generator,
    payload_bytes: float = 800.0,
    payload_noise: float = 600.0,
) -> pd.DataFrame:
    """Zaman damgalarini conn.log semasinda DataFrame'e cevir."""
    n = len(ts)
    if is_beacon:
        obytes = np.clip(rng.normal(payload_bytes, payload_noise, n), 1, None)
        durations = np.clip(rng.normal(0.5, 0.1, n), 0.05, None)
    else:
        # Insan trafigi: lognormal bayt (cok degisken), degisken sure
        obytes = rng.lognormal(np.log(max(payload_bytes, 2)), 1.2, n)
        durations = rng.lognormal(0.0, 1.0, n)
    return pd.DataFrame(
        {
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "duration": durations,
            "orig_bytes": obytes.astype(int),
            "is_beacon": is_beacon,
        }
    )


def generate_dataset(
    n_beacons: int = 5,
    n_human: int = 50,
    duration: float = 24 * 3600.0,
    start: float = 1_700_000_000.0,
    beacon_config: BeaconConfig | None = None,
    seed: int = 42,
) -> pd.DataFrame:
    """Karisik sentetik veri seti: n_beacons C2 cifti + n_human masum cift.

    Beacon periyotlari 30sn-1saat arasi log-uniform secilir (gercekci cesitlilik).
    """
    rng = np.random.default_rng(seed)
    cfg = beacon_config or BeaconConfig()
    frames: list[pd.DataFrame] = []

    for i in range(n_beacons):
        period = float(np.exp(rng.uniform(np.log(30), np.log(3600))))
        c = BeaconConfig(
            period=period,
            jitter=cfg.jitter,
            miss_prob=cfg.miss_prob,
            payload_bytes=cfg.payload_bytes,
            payload_noise=cfg.payload_noise,
        )
        ts = beacon_timestamps(c, start, duration, rng)
        frames.append(
            _pair_frame(
                ts,
                src_ip=f"10.0.0.{i + 10}",
                dst_ip=f"203.0.113.{i + 1}",
                dst_port=443,
                is_beacon=True,
                rng=rng,
                payload_bytes=c.payload_bytes,
                payload_noise=c.payload_noise,
            )
        )

    for i in range(n_human):
        rate = rng.uniform(2, 40)  # saatte 2-40 baglanti
        ts = human_timestamps(rate, start, duration, rng)
        if len(ts) == 0:
            continue
        frames.append(
            _pair_frame(
                ts,
                src_ip=f"10.0.1.{i + 10}",
                dst_ip=f"198.51.100.{i % 250 + 1}",
                dst_port=int(rng.choice([80, 443, 8080])),
                is_beacon=False,
                rng=rng,
            )
        )

    df = pd.concat(frames, ignore_index=True)
    return df.sort_values("ts").reset_index(drop=True)
