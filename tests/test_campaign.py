"""Katman 3 graf/kampanya testleri.

Test verisi dogrudan skorlanmis-cift semasiyla kurulur (score_pairs ciktisinin
kampanya katmaninin kullandigi alt kumesi): src_ip, dst_ip, dst_port, count,
score, dom_mode, in_scope.
"""

import pandas as pd

from hhunter.campaign import build_graph, detect_campaigns


def _scored(rows: list[tuple]) -> pd.DataFrame:
    """rows: (src, dst, port, score, dom_mode[, in_scope])"""
    return pd.DataFrame(
        {
            "src_ip": [r[0] for r in rows],
            "dst_ip": [r[1] for r in rows],
            "dst_port": [r[2] for r in rows],
            "count": [50] * len(rows),
            "score": [r[3] for r in rows],
            "dom_mode": [r[4] for r in rows],
            "in_scope": [r[5] if len(r) > 5 else True for r in rows],
        }
    )


def test_campaign_detected_shared_dst_same_period() -> None:
    """3 ic makine ayni hedefe ~60sn periyotla -> tek guclu kampanya."""
    df = _scored(
        [
            ("10.0.0.1", "198.51.100.7", 443, 0.9, 60.0),
            ("10.0.0.2", "198.51.100.7", 443, 0.85, 61.5),
            ("10.0.0.3", "198.51.100.7", 443, 0.8, 59.0),
            ("10.0.0.4", "203.0.113.9", 80, 0.9, 300.0),  # tek kaynak: kampanya degil
        ]
    )
    camps = detect_campaigns(df)
    assert len(camps) == 1
    c = camps.iloc[0]
    assert c["dst_ip"] == "198.51.100.7"
    assert c["n_sources"] == 3
    assert c["period_coherence"] == 1.0
    assert c["campaign_score"] > 0.5


def test_single_source_never_campaign() -> None:
    df = _scored([("10.0.0.1", "198.51.100.7", 443, 0.99, 60.0)])
    assert detect_campaigns(df).empty


def test_incoherent_periods_score_lower() -> None:
    """Ayni hedef ama cok farkli periyotlar (mesru populer servis deseni):
    tutarlilik dusuk -> kampanya skoru dusuk."""
    coherent = detect_campaigns(
        _scored(
            [
                ("10.0.0.1", "198.51.100.7", 443, 0.8, 60.0),
                ("10.0.0.2", "198.51.100.7", 443, 0.8, 62.0),
            ]
        )
    ).iloc[0]
    incoherent = detect_campaigns(
        _scored(
            [
                ("10.0.0.1", "198.51.100.7", 443, 0.8, 60.0),
                ("10.0.0.2", "198.51.100.7", 443, 0.8, 3600.0),
            ]
        )
    ).iloc[0]
    assert coherent["campaign_score"] > incoherent["campaign_score"]
    assert incoherent["period_coherence"] < 1.0


def test_low_score_and_out_of_scope_excluded() -> None:
    """Esik alti skor ve kapsam disi kanallar grafa girmez."""
    df = _scored(
        [
            ("10.0.0.1", "198.51.100.7", 443, 0.2, 60.0),  # dusuk skor
            ("10.0.0.2", "198.51.100.7", 443, 0.9, 60.0),
            ("10.0.0.3", "192.168.1.5", 161, 0.9, 60.0, False),  # kapsam disi
        ]
    )
    g = build_graph(df)
    assert g.number_of_edges() == 1
    assert detect_campaigns(df).empty  # paylasilan hedefte tek gecerli kaynak kaldi


def test_duplicate_channel_keeps_best_edge() -> None:
    """Ayni (src,dst) iki portta: graf tek kenar, yuksek skorlu olani tutar."""
    df = _scored(
        [
            ("10.0.0.1", "198.51.100.7", 443, 0.6, 60.0),
            ("10.0.0.1", "198.51.100.7", 8443, 0.9, 60.0),
        ]
    )
    g = build_graph(df)
    assert g.number_of_edges() == 1
    assert g.edges["10.0.0.1", "198.51.100.7"]["score"] == 0.9
