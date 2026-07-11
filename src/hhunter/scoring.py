"""Katman 2: skorlama - cok-sinyal birlesimi (RITA-esini bilesik skor).

Literatur dersleri (gunluk Bolum 8):
- RITA'nin final skorunun yarisi BAYT tarafidir (DataSizeScore). Jitter/burst
  zamanlamayi gizler ama beacon payload boyutu sabittir - Elastic, Emotet'i
  zamanlama degil kaynak-bayt tutarliligiyla yakaladi.
- 4 pozitif etiketle supervizeli kalibrasyon YAPILMAZ: normalize alt-skorlarin
  agirlikli ortalamasi (etiketsiz calisir) + FP butcesiyle esik.
- Baglam FP'leri eler (BAYWATCH populerlik analizi): tek makinenin gittigi
  hedef supheli; 500 makinenin gittigi hedef update/NTP sunucusudur.

Tasarim ilkesi: her alt-skor 0-1 araliginda ve "1 = beacon gibi". NaN alt-skor
"sinyal bilinmiyor" demektir; agirlikli ortalamadan paydasıyla birlikte duser
(cezalandirmaz da odullendirmez de).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from hhunter.features import extract_features

# Agirliklar: zaman ~0.60, bayt ~0.25, baglam ~0.15.
# RITA final skoru zaman/bayt yarilarini 50/50 ortalar; biz zaman tarafinda
# daha zengin (dom-kume + Schuster) oldugumuz icin zamana biraz fazla veriyoruz.
DEFAULT_WEIGHTS: dict[str, float] = {
    "s_dom": 0.25,  # baskin-kume: dom_support * (1 - dom_cv/0.3)
    "s_mad": 0.15,  # dayanikli aralik duzeni (katlanmis seri oncelikli)
    "s_schuster": 0.20,  # frekans-uzayi anlamliligi
    "s_bytes_reg": 0.15,  # bayt tutarliligi (RITA dsMADM'in oransal hali)
    "s_bytes_skew": 0.05,  # bayt simetrisi (Bowley)
    "s_bytes_small": 0.05,  # kucuk payload (RITA dsSmallness: 1 - mod/65535)
    "s_rare_dst": 0.10,  # hedef nadirligi: 1 / (o hedefe giden ic makine sayisi)
    "s_persist": 0.05,  # sureklilik: kanal, gozlem penceresinin ne kadarinda aktif
}


def byte_stats(sizes) -> dict[str, float]:
    """Bayt boyutu istatistikleri (RITA DataSizeScore'un dayanikli karsiligi).

    - bytes_mad_cv: MAD/medyan. RITA 32B SABIT esik kullanir ve buyuk-payload
      beacon'lari kacirir (bilinen FN); oransal olcu bu tuzaga dusmez.
    - bytes_bowley: ceyreklik carpikligi - beacon baytlari simetrik dagilir.
    - bytes_mode_small: 1 - mod/65535 (RITA dsSmallness). Check-in paketleri
      kucuktur; buyuk transferler (exfil degil beacon ariyoruz) skoru duserir.
    """
    s = pd.to_numeric(pd.Series(sizes), errors="coerce").dropna().to_numpy(dtype=float)
    s = s[s >= 0]
    if len(s) < 4:
        return {"bytes_mad_cv": np.nan, "bytes_bowley": np.nan, "bytes_mode_small": np.nan}
    q1, q2, q3 = np.percentile(s, [25, 50, 75])
    mad = float(np.median(np.abs(s - q2)))
    iqr = q3 - q1
    vals, counts = np.unique(np.round(s), return_counts=True)
    mode = float(vals[counts.argmax()])
    return {
        "bytes_mad_cv": mad / q2 if q2 > 0 else np.nan,
        "bytes_bowley": float((q1 + q3 - 2 * q2) / iqr) if iqr > 0 else 0.0,
        "bytes_mode_small": float(np.clip(1.0 - mode / 65535.0, 0.0, 1.0)),
    }


def _score_low(values: pd.Series, scale: float) -> pd.Series:
    """0'da 1 olan, scale'de 0'a inen dogrusal skor. NaN korunur."""
    return (1.0 - values / scale).clip(0.0, 1.0)


def compute_subscores(feats: pd.DataFrame) -> pd.DataFrame:
    """Ozellik DataFrame'inden 0-1 normalize alt-skorlar.

    s_dom, Hafta 2'nin birlesik kuralinin (dom_cv<0.15 VE dom_support>0.5)
    surekli halidir: iki sinyalin CARPIMI - biri sifirsa skor sifir, tipki
    VE kapisi gibi, ama esik yerine derece tasir (skorlama katmani esik sevmez).
    """
    out = pd.DataFrame(index=feats.index)
    out["s_dom"] = feats["dom_support"] * _score_low(feats["dom_cv"], 0.3)
    mad = feats["col_mad_cv"].fillna(feats["raw_mad_cv"])
    out["s_mad"] = _score_low(mad, 0.5)
    # sig ~30 zaten ezici kanit (p ~ e^-30); ustunu 1'e kirp
    out["s_schuster"] = (feats["schuster_sig"] / 30.0).clip(0.0, 1.0)
    out["s_bytes_reg"] = _score_low(feats["bytes_mad_cv"], 0.3)
    out["s_bytes_skew"] = _score_low(feats["bytes_bowley"].abs(), 1.0)
    out["s_bytes_small"] = feats["bytes_mode_small"]
    return out


def add_context(pairs: pd.DataFrame) -> pd.DataFrame:
    """Baglam sinyalleri: hedef nadirligi + sureklilik.

    - s_rare_dst = 1/prevalence: hedefe giden benzersiz ic kaynak sayisinin
      tersi. NTP havuzu/update CDN'ine onlarca makine gider (skor ~0), gercek
      C2 hedefine cogunlukla 1-2 enfekte makine gider (skor ~1). DIKKAT:
      kampanya katmani (Hafta 3 graf) bunun tersini kanit sayar - iki katman
      ayni sinyali farkli soruya cevap olarak kullanir, celiski degildir.
    - s_persist: (last_seen - first_seen) / gozlem penceresi. Beacon kanali
      sureklidir; 10 dakikalik bir gezinme oturumu degil.
    """
    out = pairs.copy()
    prevalence = out.groupby("dst_ip")["src_ip"].transform("nunique")
    out["dst_prevalence"] = prevalence
    out["s_rare_dst"] = 1.0 / prevalence
    window = float(out["last_seen"].max() - out["first_seen"].min())
    span = out["last_seen"] - out["first_seen"]
    out["s_persist"] = (span / window).clip(0.0, 1.0) if window > 0 else 0.0
    return out


def score_pairs(
    pairs: pd.DataFrame,
    weights: dict[str, float] | None = None,
    burst_gap: float = 5.0,
) -> pd.DataFrame:
    """Tam Katman-2 boru hatti: pairs -> ozellikler -> alt-skorlar -> bilesik skor.

    Bilesik skor: NaN-farkindalikli agirlikli ortalama. Bir cift icin bayt
    verisi yoksa bayt alt-skorlari paydan VE paydadan duser; kalan sinyaller
    kendi agirliklariyla normalize edilir. Boylece eksik veri ne odul ne ceza.

    Dondurulen DataFrame skora gore azalan siralidir; tum ozellik ve alt-skor
    kolonlarini icerir (analiz/gorsellestirme icin).
    """
    w = pd.Series(weights or DEFAULT_WEIGHTS, dtype=float)
    pairs = pairs.reset_index(drop=True)

    feats = pd.DataFrame(
        [extract_features(np.asarray(t, dtype=float), burst_gap=burst_gap) for t in pairs["timestamps"]]
    )
    if "orig_bytes_list" in pairs.columns:
        bstats = pd.DataFrame([byte_stats(b) for b in pairs["orig_bytes_list"]])
    else:
        bstats = pd.DataFrame(
            {"bytes_mad_cv": np.nan, "bytes_bowley": np.nan, "bytes_mode_small": np.nan},
            index=pairs.index,
        )
    feats = pd.concat([feats, bstats], axis=1)

    ctx = add_context(pairs)
    sub = compute_subscores(feats)
    sub["s_rare_dst"] = ctx["s_rare_dst"]
    sub["s_persist"] = ctx["s_persist"]
    sub = sub[list(w.index)]

    weighted_sum = sub.mul(w, axis=1).sum(axis=1, skipna=True)
    weight_present = sub.notna().mul(w, axis=1).sum(axis=1)
    score = weighted_sum / weight_present.replace(0.0, np.nan)

    out = pd.concat(
        [ctx[["dst_prevalence"]], pairs, feats, sub],
        axis=1,
    )
    out["score"] = score
    return out.sort_values("score", ascending=False).reset_index(drop=True)


def threshold_for_budget(scores, max_alerts: int) -> float:
    """FP butcesiyle esik secimi: 'analistim gunde en fazla N alarm inceler'.

    4 pozitif etiketle ROC/PR kalibrasyonu anlamsiz; onun yerine operasyonel
    gercekten turetilmis esik: en yuksek N. skoru esik yap. Esik degil siralama
    onemlidir - dedektorun isi supheli olani listenin basina getirmek.
    """
    s = np.sort(pd.to_numeric(pd.Series(scores), errors="coerce").dropna().to_numpy())[::-1]
    if len(s) == 0:
        return 1.0
    return float(s[min(max_alerts, len(s)) - 1])
