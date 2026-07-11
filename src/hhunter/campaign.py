"""Katman 3: graf analizi - anomaliden KAMPANYA tespitine.

Yol haritasindaki cumle: "Tek beacon anomalidir, uc beacon kampanyadir."
Tek bir supheli kanal yanlis alarm olabilir; ama AYNI dis hedefe, BENZER
periyotla beacon atan birden fazla ic makine, koordineli bir enfeksiyonun
(ayni implant, ayni C2 sunucusu) guclu kanitidir. Literatur teyidi (gunluk
Bolum 8): PeerHunter/Louvain gibi agir botnet-graf yontemleri bu olcek icin
gereksiz; NetFlow'da kanitlanmis basit desen yeterli - paylasilan hedef +
benzer imza = kampanya.

Tasarim:
- Dugumler: ic kaynaklar (src) ve dis hedefler (dst) - iki parcali (bipartite) graf
- Kenarlar: kapsam ici (in_scope) ve skor esigini gecen supheli kanallar;
  kenar ozellikleri: skor, tahmini periyot (dom_mode), port, baglanti sayisi
- Kampanya adayi: >=min_sources benzersiz ic kaynagin baglandigi hedef
- Periyot tutarliligi: kaynaklarin dom_mode'lari medyan periyodun +-tol'unde mi?
  Ayni implant konfigurasyonu ayni sleep suresi demektir; tutarlilik kampanya
  hipotezini guclendirir, tutarsizlik "populer servis" hipotezini.
- Hub merkeziligi: hedefin derece merkeziligi - cok kaynakli hedefler "hub"
  olarak isaretlenir (C2 sunucusu VEYA populer mesru servis; karar analistin,
  kanit bizim isimiz).

DIKKAT - tek-host sinirlamasi (gunluk Bolum 9-10 dersi): CTU-42 gibi tek
enfekte makineli yakalamada kampanya katmani C2'yi YAKALAYAMAZ (>=2 kaynak
sarti mekanik olarak saglanamaz). Bu katmanin gercek sinavi cok-hostlu
senaryolardir (CTU 9/10/11). Simulatorle mekanik dogrulanir.
"""

from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd

# Kampanya adayi olmak icin gereken minimum bilesik skor. threshold_for_budget
# ile operasyonel butceden de turetilebilir; varsayilan, CTU-42'de kapsam ici
# medyanin belirgin ustunde kalan "supheli" bandi hedefler.
DEFAULT_MIN_SCORE = 0.5


def build_graph(
    scored: pd.DataFrame,
    min_score: float = DEFAULT_MIN_SCORE,
    require_in_scope: bool = True,
) -> nx.Graph:
    """Skorlanmis ciftlerden iki parcali supheli-kanal grafi kur.

    Dugum ozellikleri: bipartite=0 (ic kaynak) / 1 (dis hedef).
    Kenar ozellikleri: score, period (dom_mode), port, count.
    """
    cand = scored[scored["score"] >= min_score]
    if require_in_scope and "in_scope" in cand.columns:
        cand = cand[cand["in_scope"]]

    g = nx.Graph()
    for _, r in cand.iterrows():
        src, dst = str(r["src_ip"]), str(r["dst_ip"])
        g.add_node(src, bipartite=0)
        g.add_node(dst, bipartite=1)
        # Ayni (src,dst) farkli portlarda birden fazla kanal olabilir;
        # en yuksek skorlu kenari tut (graf sadelestirme).
        prev = g.edges.get((src, dst))
        if prev is None or r["score"] > prev["score"]:
            g.add_edge(
                src,
                dst,
                score=float(r["score"]),
                period=float(r["dom_mode"]) if pd.notna(r["dom_mode"]) else np.nan,
                port=int(r["dst_port"]) if pd.notna(r["dst_port"]) else -1,
                count=int(r["count"]),
            )
    return g


def _period_coherence(periods: list[float], tol: float = 0.25) -> float:
    """Periyotlarin ne kadari medyanin +-tol bandinda? (0-1)

    Ayni implant konfigurasyonunu paylasan makineler ayni sleep/jitter'la
    beacon atar -> periyotlar kumelesir. Farkli nedenlerle ayni hedefe giden
    mesru istemciler (orn. herkes kendi mail-poll araligiyla) dagilir.
    """
    p = np.array([x for x in periods if np.isfinite(x)])
    if len(p) == 0:
        return 0.0
    med = float(np.median(p))
    if med <= 0:
        return 0.0
    return float(np.mean(np.abs(p - med) <= tol * med))


def detect_campaigns(
    scored: pd.DataFrame,
    min_score: float = DEFAULT_MIN_SCORE,
    min_sources: int = 2,
    period_tol: float = 0.25,
    require_in_scope: bool = True,
) -> pd.DataFrame:
    """Kampanya adaylarini cikar: >=min_sources ic kaynagin paylastigi hedefler.

    Dondurulen DataFrame (kampanya skoruna gore azalan):
    - dst_ip, n_sources, sources (liste), ports (liste)
    - period_median, period_coherence (0-1)
    - mean_score: kanallarin ortalama bilesik skoru
    - degree_centrality: hedefin graf merkeziligi (hub gostergesi)
    - campaign_score = mean_score * period_coherence * (1 - 1/n_sources):
      cok kaynak + tutarli periyot + guclu kanallar carpimsal birlesir;
      n_sources=1'de sifirlanir (tek kaynak kampanya degildir), kaynak
      sayisi arttikca 1'e yaklasir.
    """
    g = build_graph(scored, min_score=min_score, require_in_scope=require_in_scope)
    dsts = [n for n, b in g.nodes(data="bipartite") if b == 1]
    centrality = nx.degree_centrality(g) if g.number_of_nodes() > 1 else {}

    rows = []
    for dst in dsts:
        srcs = sorted(g.neighbors(dst))
        if len(srcs) < min_sources:
            continue
        edges = [g.edges[s, dst] for s in srcs]
        periods = [e["period"] for e in edges]
        coherence = _period_coherence(periods, tol=period_tol)
        mean_score = float(np.mean([e["score"] for e in edges]))
        finite = [p for p in periods if np.isfinite(p)]
        rows.append(
            {
                "dst_ip": dst,
                "n_sources": len(srcs),
                "sources": srcs,
                "ports": sorted({e["port"] for e in edges}),
                "period_median": float(np.median(finite)) if finite else np.nan,
                "period_coherence": coherence,
                "mean_score": mean_score,
                "degree_centrality": float(centrality.get(dst, 0.0)),
                "campaign_score": mean_score * coherence * (1.0 - 1.0 / len(srcs)),
            }
        )
    cols = [
        "dst_ip",
        "n_sources",
        "sources",
        "ports",
        "period_median",
        "period_coherence",
        "mean_score",
        "degree_centrality",
        "campaign_score",
    ]
    out = pd.DataFrame(rows, columns=cols)
    return out.sort_values("campaign_score", ascending=False).reset_index(drop=True)
