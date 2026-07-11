"""Katman 2 skorlama testleri: bayt sinyalleri, baglam, bilesik skor, FP butcesi."""

import numpy as np
import pandas as pd
import pytest

from hhunter.features import permutation_significance
from hhunter.ingest import group_pairs
from hhunter.scoring import byte_stats, score_pairs, threshold_for_budget
from hhunter.simulator import generate_dataset


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(5)


def test_byte_stats_beacon_vs_human(rng) -> None:
    """Beacon baytlari dar ve simetrik; insan baytlari lognormal-genis."""
    beacon = rng.normal(120, 4, 100)  # sabit check-in boyutu + kucuk oynama
    human = rng.lognormal(np.log(800), 1.2, 100)
    b, h = byte_stats(beacon), byte_stats(human)
    assert b["bytes_mad_cv"] < 0.1
    assert h["bytes_mad_cv"] > 0.3
    assert abs(b["bytes_bowley"]) < 0.3
    assert b["bytes_mode_small"] > 0.99  # 120B << 65535B


def test_byte_stats_short_series_is_nan() -> None:
    s = byte_stats([100, 100])
    assert np.isnan(s["bytes_mad_cv"])


def test_beacons_rank_top_on_simulated() -> None:
    """Ana kabul testi: bilesik skor, beacon'lari listenin tepesine koymali."""
    df = generate_dataset(n_beacons=5, n_human=40, duration=12 * 3600, seed=3)
    pairs = group_pairs(df, min_connections=8)
    scored = score_pairs(pairs)
    # En ustteki 5 cift beacon olmali (5 beacon var)
    assert scored.head(5)["is_beacon"].all()
    # Ayrisim: beacon medyan skoru insanlardan belirgin yuksek
    med_b = scored[scored["is_beacon"]]["score"].median()
    med_h = scored[~scored["is_beacon"]]["score"].median()
    assert med_b > med_h + 0.25


def test_prevalence_stays_out_of_channel_score() -> None:
    """S9 dersi (gunluk Bolum 13): hedef nadirligi KANAL skoruna girmez.

    Cok-bot'lu yakalamada nadirlik tersine doner (10 bot ayni C2'ye gidince
    C2 'populer' gorunur ve cezalanir). Ayni zamansal desenle nadir ve populer
    hedef AYNI kanal skorunu almali; nadirlik bilgisi ciktida tasinir
    (s_rare_dst kolonu) ve tuketicisi kampanya katmanidir."""
    base = np.arange(0, 6 * 3600, 60.0)
    rows = [("10.0.0.%d" % i, "203.0.113.9", base) for i in range(5)]  # populer hedef
    rows.append(("10.0.0.99", "198.51.100.7", base))  # nadir hedef
    pairs = pd.DataFrame(
        {
            "src_ip": [r[0] for r in rows],
            "dst_ip": [r[1] for r in rows],
            "dst_port": 443,
            "timestamps": [r[2] for r in rows],
            "count": [len(r[2]) for r in rows],
            "first_seen": [r[2][0] for r in rows],
            "last_seen": [r[2][-1] for r in rows],
        }
    )
    scored = score_pairs(pairs)
    rare = scored[scored["dst_ip"] == "198.51.100.7"]["score"].iloc[0]
    popular = scored[scored["dst_ip"] == "203.0.113.9"]["score"].max()
    assert abs(rare - popular) < 1e-9  # ayni desen = ayni skor
    assert "s_rare_dst" in scored.columns  # bilgi kaybolmaz, kampanya katmanina akar


def test_missing_bytes_not_penalized() -> None:
    """Bayt verisi olmayan cift NaN-farkindalikli ortalamayla skorlanabilmeli."""
    base = np.arange(0, 6 * 3600, 60.0)
    pairs = pd.DataFrame(
        {
            "src_ip": ["10.0.0.1"],
            "dst_ip": ["203.0.113.1"],
            "dst_port": [443],
            "timestamps": [base],
            "count": [len(base)],
            "first_seen": [base[0]],
            "last_seen": [base[-1]],
        }
    )
    scored = score_pairs(pairs)
    assert not scored["score"].isna().any()
    assert scored["score"].iloc[0] > 0.7  # temiz beacon, bayt sinyali olmadan da yuksek


def test_threshold_for_budget() -> None:
    scores = [0.9, 0.8, 0.7, 0.6, 0.5]
    t = threshold_for_budget(scores, max_alerts=2)
    assert t == 0.8
    assert sum(s >= t for s in scores) == 2
    # Butce eleman sayisindan buyukse en dusuk skor doner
    assert threshold_for_budget(scores, max_alerts=99) == 0.5
    # Butce 0: hicbir skor esigi gecememeli (kenar durum)
    assert not any(s >= threshold_for_budget(scores, max_alerts=0) for s in scores)


def _mini_pairs(rows: list[tuple[str, str, int]]) -> pd.DataFrame:
    """(src, dst, port) listesinden ayni temiz beacon desenli pairs tablosu."""
    base = np.arange(0, 6 * 3600, 60.0)
    return pd.DataFrame(
        {
            "src_ip": [r[0] for r in rows],
            "dst_ip": [r[1] for r in rows],
            "dst_port": [r[2] for r in rows],
            "timestamps": [base] * len(rows),
            "count": [len(base)] * len(rows),
            "first_seen": [base[0]] * len(rows),
            "last_seen": [base[-1]] * len(rows),
        }
    )


def test_scope_funnel_direction_and_ports() -> None:
    """Huni kapsami: ic hedef ve altyapi portu kapsam disi, dis+web ici."""
    scored = score_pairs(
        _mini_pairs(
            [
                ("10.0.0.1", "192.168.1.5", 27001),  # ic hedef (RFC1918) -> disi
                ("10.0.0.1", "129.6.15.28", 123),  # NTP: dis ama altyapi portu -> disi
                # NOT: 203.0.113.x (TEST-NET) ipaddress'te 'private' sayilir -
                # kapsam testi icin gercek kamu IP'si gerekir
                ("10.0.0.1", "93.184.216.34", 443),  # dis + web -> ici
                ("10.0.0.1", "147.32.30.4", 80),  # kurulusun kamu blogu -> disi
            ]
        ),
        internal_nets=["147.32.0.0/16"],
    )
    scope = scored.set_index("dst_ip")["in_scope"]
    assert not scope["192.168.1.5"]
    assert not scope["129.6.15.28"]
    assert scope["93.184.216.34"]
    assert not scope["147.32.30.4"]


def test_port_category_affects_score() -> None:
    """Ayni desen: standart-disi dis port, altyapi portundan yuksek skor almali."""
    scored = score_pairs(
        _mini_pairs(
            [
                ("10.0.0.1", "203.0.113.1", 888),  # standart-disi
                ("10.0.0.2", "203.0.113.2", 443),  # web (notr)
                ("10.0.0.3", "203.0.113.3", 123),  # altyapi
            ]
        )
    )
    by_port = scored.set_index("dst_port")["score"]
    assert by_port[888] > by_port[443] > by_port[123]


def test_permutation_significance_beacon_vs_poisson(rng) -> None:
    """BAYWATCH-esini dogrulama: beacon'da p kucuk, Poisson'da buyuk olmali."""
    from hhunter.simulator import BeaconConfig, beacon_timestamps, human_timestamps

    beacon = beacon_timestamps(BeaconConfig(period=60.0, jitter=0.1), 0.0, 6 * 3600, rng)
    poisson = human_timestamps(rate_per_hour=60, start=0.0, duration=6 * 3600, rng=rng)
    pb = permutation_significance(beacon, n_perm=50)
    pp = permutation_significance(poisson, n_perm=50)
    assert pb["perm_pvalue"] <= 1 / 50 + 1e-9  # hicbir permutasyon tepeyi asamadi
    assert pb["perm_ratio"] > 3
    assert pp["perm_pvalue"] > 0.1  # rastgele seri karistirilmis halinden farksiz


def test_permutation_robust_to_bursts(rng) -> None:
    """Permutasyonun varlik sebebi: burst'lu ama periyodik OLMAYAN trafik
    analitik Exp(1) esigini kandirabilir; ampirik null kanmamali."""
    from hhunter.simulator import human_timestamps

    base = human_timestamps(rate_per_hour=20, start=0.0, duration=6 * 3600, rng=rng)
    # Her olaya rastgele 0-3 hizli tekrar ekle (burst) - periyodiklik yok
    extras = [base + rng.uniform(0.1, 3.0) for _ in range(3)]
    bursty = np.sort(np.concatenate([base, *extras]))
    p = permutation_significance(bursty, n_perm=50)
    assert p["perm_pvalue"] > 0.1
